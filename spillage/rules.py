"""Detection rules.

Every rule is a small strategy object with one job: given a string, yield the secrets in it.
Most rules are a precise regex plus a cheap keyword pre-check, some add a validator
(GitHub's CRC32 checksum, a JWT that has to decode, a password that isn't a placeholder).

Precision matters more than recall here. A scanner that cries wolf on every UUID gets
uninstalled, so the generic rules only fire with a key-ish name next to them and enough
entropy, and anything that looks like a placeholder is dropped.
"""

from __future__ import annotations

import base64
import binascii
import json
import math
import re
import zlib
from collections import Counter
from dataclasses import dataclass, field
from typing import Callable, Iterator, Optional, Sequence

from .models import Severity

_BASE62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

PLACEHOLDER_WORDS = (
    "example",
    "sample",
    "dummy",
    "placeholder",
    "changeme",
    "change_me",
    "your_",
    "your-",
    "yourkey",
    "redacted",
    "xxxxxx",
    "******",
    "<",
    "${",
    "{{",
    "$(",
    "%s",
    "…",
    "...",
    "fake",
    "test123",
    "insert",
    "replace",
    "todo",
    "spillage",
)


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    total = len(value)
    return -sum(n / total * math.log2(n / total) for n in counts.values())


def looks_like_placeholder(value: str) -> bool:
    low = value.lower()
    if any(word in low for word in PLACEHOLDER_WORDS):
        return True
    # aaaaaaaa, 12345678, abcdefgh…
    if len(set(low)) <= 3:
        return True
    return low in {"password", "secret", "token", "none", "null", "undefined", "true", "false"}


def github_checksum_ok(token: str) -> bool:
    """New-style GitHub tokens end in a base62 CRC32 of the 30 random characters before it."""
    body, check = token[4:-6], token[-6:]
    n = zlib.crc32(body.encode())
    digits = ""
    while n:
        n, r = divmod(n, 62)
        digits = _BASE62[r] + digits
    return digits.rjust(6, "0") == check


def _b64json(part: str) -> Optional[dict]:
    try:
        raw = base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))
        data = json.loads(raw)
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return None
    return data if isinstance(data, dict) else None


def jwt_ok(token: str) -> bool:
    parts = token.split(".")
    if len(parts) != 3:
        return False
    header = _b64json(parts[0])
    return bool(header and "alg" in header and _b64json(parts[1]) is not None)


def jwt_is_public(token: str) -> bool:
    """Supabase anon keys and similar are meant to ship to browsers."""
    payload = _b64json(token.split(".")[1]) or {}
    return payload.get("role") == "anon"


@dataclass(frozen=True)
class Match:
    secret: str
    start: int
    end: int


_TOKEN_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-")


def left_boundary_ok(text: str, start: int) -> bool:
    """True if a match at `start` isn't the tail of a longer token.

    A JSON escape like `\\n` right before the match counts as a boundary, since that is how a
    line break looks in the raw log file.
    """
    if start == 0 or text[start - 1] not in _TOKEN_CHARS:
        return True
    return start >= 2 and text[start - 2] == "\\" and text[start - 1] in "ntr"


@dataclass
class Rule:
    """A regex rule. `group` picks the capture that is the secret itself.

    Patterns start with a literal where possible: Python's regex engine then jumps straight to
    candidate positions instead of trying every offset, which is the difference between 0.2 s
    and 6 s on a few hundred megabytes of logs. The left word boundary is checked in Python
    for the same reason.
    """

    id: str
    name: str
    provider: str
    pattern: str
    severity: Severity = Severity.HIGH
    keywords: Sequence[str] = ()
    rotate_url: str = ""
    group: int = 0
    flags: int = 0
    min_entropy: float = 0.0
    validator: Optional[Callable[[str], bool]] = None
    check_placeholder: bool = False
    boundary: bool = True
    _regex: re.Pattern = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self._regex = re.compile(self.pattern, self.flags)

    def might_match(self, text: str) -> bool:
        return not self.keywords or any(k in text for k in self.keywords)

    def candidates(self, text: str) -> Iterator[re.Match]:
        return self._regex.finditer(text)

    def find(self, text: str) -> Iterator[Match]:
        if not self.might_match(text):
            return
        for m in self.candidates(text):
            secret = m.group(self.group)
            start = m.start(self.group)
            if not secret:
                continue
            if self.boundary and not left_boundary_ok(text, start):
                continue
            if self.accept(secret):
                yield Match(secret, start, m.end(self.group))

    def accept(self, secret: str) -> bool:
        if self.min_entropy and shannon_entropy(secret) < self.min_entropy:
            return False
        if self.check_placeholder and looks_like_placeholder(secret):
            return False
        return not self.validator or self.validator(secret)

    def severity_for(self, secret: str) -> Severity:
        return self.severity


class StripeRule(Rule):
    """Live Stripe keys can move money, test keys can't."""

    def severity_for(self, secret: str) -> Severity:
        return Severity.CRITICAL if "_live_" in secret else Severity.LOW


class JwtRule(Rule):
    def severity_for(self, secret: str) -> Severity:
        return Severity.LOW if jwt_is_public(secret) else Severity.MEDIUM


class DiscordBotRule(Rule):
    """Discord bot tokens have no fixed prefix, so the pattern anchors on the two dots in the
    middle and the first segment (the bot id in base64) is found by walking left."""

    def candidates(self, text: str) -> Iterator[re.Match]:
        return self._regex.finditer(text)

    def find(self, text: str) -> Iterator[Match]:
        for m in self._regex.finditer(text):
            dot = m.start()
            for width in range(27, 23, -1):
                start = dot - width
                if start < 0:
                    continue
                head = text[start:dot]
                if head[0] in "MNO" and all(c in _TOKEN_CHARS for c in head) and left_boundary_ok(text, start):
                    secret = text[start : m.end()]
                    if self.accept(secret):
                        yield Match(secret, start, m.end())
                    break


class AnchoredRule(Rule):
    """For patterns without a single literal prefix: find each anchor with str.find (fast, in C)
    and run the regex only right there, instead of letting it try every offset."""

    anchors: Sequence[str] = ()

    def __init__(self, *args, anchors: Sequence[str] = (), **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.anchors = tuple(anchors)

    def find(self, text: str) -> Iterator[Match]:
        for anchor in self.anchors:
            pos = text.find(anchor)
            while pos != -1:
                if not self.boundary or left_boundary_ok(text, pos):
                    m = self._regex.match(text, pos)
                    if m and m.group(self.group) and self.accept(m.group(self.group)):
                        yield Match(m.group(self.group), m.start(self.group), m.end(self.group))
                pos = text.find(anchor, pos + 1)


_KEY_WORDS = ("key", "secret", "token", "password", "passwd", "pwd", "bearer")
_KEY_PREFIXES = (
    "api", "secret", "private", "access", "auth", "refresh", "client", "app", "master",
    "signing", "encryption", "session", "admin", "service", "webhook", "db", "database",
    "user", "root", "login", "account",
)


class GenericSecretRule(Rule):
    """`API_KEY = "..."`, `"client_secret": "..."`, `password: ...`, `Bearer ...`.

    Every key-ish name ends in one of a handful of words, so we look those up with str.find
    (fast, in C) and only then run the regex anchored right there. The word has to start a
    name or finish a known one: `monkey = ...` does not count.
    """

    def find(self, text: str) -> Iterator[Match]:
        seen = set()
        for word in _KEY_WORDS:
            for variant in {word, word.capitalize(), word.upper()}:
                pos = text.find(variant)
                while pos != -1:
                    if pos not in seen and self._name_ok(text, pos, variant):
                        seen.add(pos)
                        regex = _BEARER_TAIL if word == "bearer" else self._regex
                        m = regex.match(text, pos + len(variant))
                        if m:
                            secret = m.group(self.group)
                            if self.accept(secret):
                                yield Match(secret, m.start(self.group), m.end(self.group))
                    pos = text.find(variant, pos + 1)

    @staticmethod
    def _name_ok(text: str, pos: int, word: str) -> bool:
        if pos == 0:
            return True
        prev = text[pos - 1]
        if prev not in _TOKEN_CHARS or prev in "_-":
            return True
        if word[0].isupper() and prev.islower():  # apiKey, clientSecret
            return True
        before = text[max(0, pos - 12) : pos].lower()
        return before.endswith(_KEY_PREFIXES)


# After the key word: optional closing quote (maybe escaped, as it is inside a JSON log line),
# an assignment, an optional opening quote, then the value.
_ASSIGN_TAIL = (
    r"(?:\\?[\"'])?\s{0,3}(?:=>|:=|:|=)\s{0,3}(?:\\?[\"'])?"
    r"([A-Za-z0-9_\-+/=.!@#$%^&*~]{16,128})(?![A-Za-z0-9_\-+/=])"
)
# `Authorization: Bearer <token>` has a space instead of an assignment.
_BEARER_TAIL = re.compile(r"[ \t]{1,3}([A-Za-z0-9_\-+/=.~]{16,512})(?![A-Za-z0-9_\-+/=])")

_E = r"(?![A-Za-z0-9_\-])"  # right boundary: not followed by more token characters

BUILTIN_RULES: list = [
    # ---- AI providers -------------------------------------------------------------------
    Rule(
        "claude-oauth-token", "Claude Code OAuth token", "Anthropic",
        r"(sk-ant-o(?:at|rt)\d\d-[A-Za-z0-9_\-]{60,160})" + _E,
        Severity.CRITICAL, ("sk-ant-oat", "sk-ant-ort"), "https://claude.ai/settings/claude-code", group=1,
    ),
    Rule(
        "anthropic-api-key", "Anthropic API key", "Anthropic",
        r"(sk-ant-(?:api|admin)\d\d-[A-Za-z0-9_\-]{80,120})" + _E,
        Severity.CRITICAL, ("sk-ant-",), "https://console.anthropic.com/settings/keys", group=1,
    ),
    Rule(
        "openai-api-key", "OpenAI API key", "OpenAI",
        r"(sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{20,200}T3BlbkFJ[A-Za-z0-9_\-]{20,200})" + _E,
        Severity.CRITICAL, ("T3BlbkFJ",), "https://platform.openai.com/api-keys", group=1,
    ),
    Rule(
        "openai-project-key", "OpenAI project key", "OpenAI",
        r"(sk-(?:proj|svcacct|admin)-[A-Za-z0-9_\-]{80,200})" + _E,
        Severity.CRITICAL, ("sk-proj-", "sk-svcacct-", "sk-admin-"), "https://platform.openai.com/api-keys",
        group=1, min_entropy=4.0,
    ),
    Rule(
        "openrouter-api-key", "OpenRouter API key", "OpenRouter",
        r"(sk-or-v1-[a-f0-9]{64})" + _E,
        Severity.CRITICAL, ("sk-or-v1-",), "https://openrouter.ai/settings/keys", group=1,
    ),
    Rule(
        "google-api-key", "Google API key", "Google",
        r"(AIza[0-9A-Za-z_\-]{35})" + _E,
        Severity.HIGH, ("AIza",), "https://console.cloud.google.com/apis/credentials", group=1,
    ),
    Rule(
        "google-oauth-secret", "Google OAuth client secret", "Google",
        r"(GOCSPX-[A-Za-z0-9_\-]{28})" + _E,
        Severity.HIGH, ("GOCSPX-",), "https://console.cloud.google.com/apis/credentials", group=1,
    ),
    Rule(
        "huggingface-token", "Hugging Face token", "Hugging Face",
        r"(hf_[A-Za-z]{34})" + _E,
        Severity.HIGH, ("hf_",), "https://huggingface.co/settings/tokens", group=1, min_entropy=3.5,
    ),
    Rule(
        "groq-api-key", "Groq API key", "Groq",
        r"(gsk_[A-Za-z0-9]{52})" + _E,
        Severity.HIGH, ("gsk_",), "https://console.groq.com/keys", group=1,
    ),
    Rule(
        "xai-api-key", "xAI API key", "xAI",
        r"(xai-[A-Za-z0-9]{80})" + _E,
        Severity.HIGH, ("xai-",), "https://console.x.ai", group=1,
    ),
    Rule(
        "perplexity-api-key", "Perplexity API key", "Perplexity",
        r"(pplx-[A-Za-z0-9]{48})" + _E,
        Severity.HIGH, ("pplx-",), "https://www.perplexity.ai/settings/api", group=1,
    ),
    Rule(
        "replicate-api-token", "Replicate API token", "Replicate",
        r"(r8_[A-Za-z0-9]{37})" + _E,
        Severity.HIGH, ("r8_",), "https://replicate.com/account/api-tokens", group=1, min_entropy=3.5,
    ),
    Rule(
        "langsmith-api-key", "LangSmith API key", "LangChain",
        r"(lsv2_(?:pt|sk)_[a-f0-9]{32}_[a-f0-9]{10})" + _E,
        Severity.HIGH, ("lsv2_",), "https://smith.langchain.com/settings", group=1,
    ),
    Rule(
        "pinecone-api-key", "Pinecone API key", "Pinecone",
        r"(pcsk_[A-Za-z0-9]{5,8}_[A-Za-z0-9]{40,90})" + _E,
        Severity.HIGH, ("pcsk_",), "https://app.pinecone.io", group=1, min_entropy=4.0,
    ),
    Rule(
        "tavily-api-key", "Tavily API key", "Tavily",
        r"(tvly-(?:dev-|prod-)?[A-Za-z0-9]{32})" + _E,
        Severity.HIGH, ("tvly-",), "https://app.tavily.com", group=1, min_entropy=3.5,
    ),
    Rule(
        "firecrawl-api-key", "Firecrawl API key", "Firecrawl",
        r"(fc-[a-f0-9]{32})" + _E,
        Severity.HIGH, ("fc-",), "https://www.firecrawl.dev/app/api-keys", group=1, min_entropy=3.2,
    ),
    Rule(
        "supabase-secret-key", "Supabase secret key", "Supabase",
        r"(sb_secret_[A-Za-z0-9_\-]{30,48})" + _E,
        Severity.CRITICAL, ("sb_secret_",), "https://supabase.com/dashboard/project/_/settings/api-keys", group=1,
        min_entropy=3.5,
    ),
    Rule(
        "resend-api-key", "Resend API key", "Resend",
        r"(re_[A-Za-z0-9]{8}_[A-Za-z0-9]{24})" + _E,
        Severity.HIGH, ("re_",), "https://resend.com/api-keys", group=1, min_entropy=3.8,
    ),
    Rule(
        "posthog-personal-key", "PostHog personal API key", "PostHog",
        r"(phx_[A-Za-z0-9]{40,50})" + _E,
        Severity.HIGH, ("phx_",), "https://app.posthog.com/settings/user-api-keys", group=1, min_entropy=3.8,
    ),
    Rule(
        "vercel-blob-token", "Vercel Blob token", "Vercel",
        r"(vercel_blob_rw_[A-Za-z0-9]{16}_[A-Za-z0-9]{30})" + _E,
        Severity.HIGH, ("vercel_blob_rw_",), "https://vercel.com/dashboard/stores", group=1,
    ),
    # ---- Code hosting and package registries ---------------------------------------------
    Rule(
        "github-token", "GitHub token", "GitHub",
        r"(gh[pousr]_[A-Za-z0-9]{36})" + _E,
        Severity.CRITICAL, ("ghp_", "gho_", "ghu_", "ghs_", "ghr_"), "https://github.com/settings/tokens",
        group=1, validator=github_checksum_ok,
    ),
    Rule(
        "github-fine-grained-pat", "GitHub fine-grained token", "GitHub",
        r"(github_pat_[A-Za-z0-9_]{82})" + _E,
        Severity.CRITICAL, ("github_pat_",), "https://github.com/settings/tokens?type=beta", group=1,
    ),
    Rule(
        "gitlab-token", "GitLab token", "GitLab",
        r"(glpat-[A-Za-z0-9_\-]{20,})" + _E,
        Severity.CRITICAL, ("glpat-",), "https://gitlab.com/-/user_settings/personal_access_tokens", group=1,
    ),
    Rule(
        "npm-token", "npm access token", "npm",
        r"(npm_[A-Za-z0-9]{36})" + _E,
        Severity.CRITICAL, ("npm_",), "https://www.npmjs.com/settings/~/tokens", group=1, min_entropy=3.5,
    ),
    Rule(
        "pypi-token", "PyPI upload token", "PyPI",
        r"(pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,})" + _E,
        Severity.CRITICAL, ("pypi-AgEIcHlwaS5vcmc",), "https://pypi.org/manage/account/token/", group=1,
    ),
    # ---- Cloud ---------------------------------------------------------------------------
    Rule(
        "aws-access-key-id", "AWS access key ID", "AWS",
        r"((?:AKIA|ASIA)[0-9A-Z]{16})" + _E,
        Severity.HIGH, ("AKIA", "ASIA"), "https://console.aws.amazon.com/iam/home#/security_credentials",
        group=1, validator=lambda s: "EXAMPLE" not in s,
    ),
    AnchoredRule(
        "aws-secret-access-key", "AWS secret access key", "AWS",
        r"(?:aws|AWS|Aws)[_-]?(?:secret|SECRET|Secret)[_-]?(?:(?:access|ACCESS|Access)[_-]?)?(?:key|KEY|Key)"
        r"(?:\\?[\"'])?\s{0,3}[:=]\s{0,3}(?:\\?[\"'])?([A-Za-z0-9/+]{40})(?![A-Za-z0-9/+])",
        Severity.CRITICAL, (), "https://console.aws.amazon.com/iam/home#/security_credentials",
        group=1, min_entropy=4.0, check_placeholder=True, boundary=False,
        anchors=("aws_secret", "AWS_SECRET", "awsSecret", "AwsSecret", "aws-secret", "awssecret"),
    ),
    Rule(
        "digitalocean-token", "DigitalOcean token", "DigitalOcean",
        r"(do[por]_v1_[a-f0-9]{64})" + _E,
        Severity.CRITICAL, ("dop_v1_", "doo_v1_", "dor_v1_"), "https://cloud.digitalocean.com/account/api/tokens",
        group=1,
    ),
    Rule(
        "databricks-token", "Databricks token", "Databricks",
        r"(dapi[a-f0-9]{32}(?:-\d)?)" + _E,
        Severity.HIGH, ("dapi",), "", group=1, min_entropy=3.0,
    ),
    Rule(
        "google-oauth-refresh-token", "Google OAuth refresh token", "Google",
        r"(1//0[A-Za-z0-9_\-]{40,120})" + _E,
        Severity.HIGH, ("1//0",), "https://myaccount.google.com/permissions", group=1, min_entropy=4.0,
    ),
    Rule(
        "google-oauth-access-token", "Google OAuth access token", "Google",
        r"(ya29\.[A-Za-z0-9_\-]{50,})" + _E,
        Severity.LOW, ("ya29.",), "", group=1, min_entropy=4.0,
    ),
    Rule(
        "doppler-token", "Doppler token", "Doppler",
        r"(dp\.(?:pt|st|sa|ct|scim|audit)\.[A-Za-z0-9]{40,44})" + _E,
        Severity.CRITICAL, ("dp.",), "https://dashboard.doppler.com", group=1, min_entropy=4.0,
    ),
    Rule(
        "vault-token", "HashiCorp Vault token", "HashiCorp",
        r"(hv[sb]\.[A-Za-z0-9_\-]{90,300})" + _E,
        Severity.CRITICAL, ("hvs.", "hvb."), "", group=1, min_entropy=4.0,
    ),
    Rule(
        "1password-service-account", "1Password service account token", "1Password",
        r"(ops_eyJ[A-Za-z0-9+/]{250,}={0,3})",
        Severity.CRITICAL, ("ops_eyJ",), "https://my.1password.com/developer-tools", group=1,
    ),
    Rule(
        "planetscale-token", "PlanetScale token or password", "PlanetScale",
        r"(pscale_(?:tkn|pw|oauth)_[A-Za-z0-9_=.\-]{32,64})" + _E,
        Severity.HIGH, ("pscale_",), "https://app.planetscale.com", group=1, min_entropy=3.8,
    ),
    # ---- Payments and SaaS ---------------------------------------------------------------
    StripeRule(
        "stripe-secret-key", "Stripe secret key", "Stripe",
        r"((?:sk|rk)_(?:live|test)_[0-9A-Za-z]{24,99})" + _E,
        Severity.CRITICAL, ("sk_live_", "sk_test_", "rk_live_", "rk_test_"),
        "https://dashboard.stripe.com/apikeys", group=1,
    ),
    Rule(
        "slack-token", "Slack token", "Slack",
        r"(xox[abposr]-[0-9A-Za-z\-]{10,250})" + _E,
        Severity.HIGH, ("xox",), "https://api.slack.com/apps",
        group=1, min_entropy=3.0,
    ),
    Rule(
        "slack-webhook", "Slack webhook URL", "Slack",
        r"(https://hooks\.slack\.com/(?:services|workflows|triggers)/[A-Za-z0-9+/_\-]{20,})",
        Severity.MEDIUM, ("hooks.slack.com",), "https://api.slack.com/apps", group=1,
    ),
    Rule(
        "discord-webhook", "Discord webhook URL", "Discord",
        r"(https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d{15,22}/[A-Za-z0-9_\-]{60,70})",
        Severity.MEDIUM, ("discord.com/api/webhooks", "discordapp.com/api/webhooks"), "", group=1,
    ),
    DiscordBotRule(
        "discord-bot-token", "Discord bot token", "Discord",
        r"\.[A-Za-z0-9_\-]{6}\.[A-Za-z0-9_\-]{27,40}" + _E,
        Severity.HIGH, (), "https://discord.com/developers/applications", min_entropy=4.0,
        validator=lambda s: not s.startswith("eyJ") and _discord_id_ok(s),
    ),
    Rule(
        "telegram-bot-token", "Telegram bot token", "Telegram",
        r"(\d{8,10}:AA[0-9A-Za-z_\-]{33})" + _E,
        Severity.HIGH, (":AA",), "https://t.me/BotFather", group=1,
    ),
    Rule(
        "sendgrid-api-key", "SendGrid API key", "SendGrid",
        r"(SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43})" + _E,
        Severity.HIGH, ("SG.",), "https://app.sendgrid.com/settings/api_keys", group=1,
    ),
    Rule(
        "twilio-api-key", "Twilio API key", "Twilio",
        r"(SK[0-9a-f]{32})" + _E,
        Severity.HIGH, ("SK",), "https://console.twilio.com", group=1, min_entropy=3.3,
    ),
    Rule(
        "shopify-token", "Shopify access token", "Shopify",
        r"(shp(?:at|ca|pa|ss)_[a-fA-F0-9]{32})" + _E,
        Severity.HIGH, ("shpat_", "shpca_", "shppa_", "shpss_"), "", group=1,
    ),
    Rule(
        "brevo-api-key", "Brevo API key", "Brevo",
        r"(xkeysib-[a-f0-9]{64}-[A-Za-z0-9]{16})" + _E,
        Severity.HIGH, ("xkeysib-",), "https://app.brevo.com/settings/keys/api", group=1,
    ),
    Rule(
        "linear-api-key", "Linear API key", "Linear",
        r"(lin_api_[A-Za-z0-9]{40})" + _E,
        Severity.HIGH, ("lin_api_",), "https://linear.app/settings/account/security", group=1,
    ),
    Rule(
        "notion-token", "Notion integration token", "Notion",
        r"((?:secret_[A-Za-z0-9]{43}|ntn_[0-9]{11}[A-Za-z0-9]{35}))" + _E,
        Severity.HIGH, ("secret_", "ntn_"), "https://www.notion.so/my-integrations", group=1, min_entropy=3.8,
    ),
    Rule(
        "sentry-token", "Sentry auth token", "Sentry",
        r"(sntr[ysu]_[A-Za-z0-9+/=_\-]{40,})" + _E,
        Severity.MEDIUM, ("sntrys_", "sntryu_"), "https://sentry.io/settings/account/api/auth-tokens/", group=1,
    ),
    Rule(
        "grafana-token", "Grafana service account token", "Grafana",
        r"(glsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8})" + _E,
        Severity.HIGH, ("glsa_",), "", group=1,
    ),
    Rule(
        "postman-api-key", "Postman API key", "Postman",
        r"(PMAK-[a-f0-9]{24}-[a-f0-9]{34})" + _E,
        Severity.HIGH, ("PMAK-",), "https://go.postman.co/settings/me/api-keys", group=1,
    ),
    Rule(
        "atlassian-api-token", "Atlassian API token", "Atlassian",
        r"(ATATT3[A-Za-z0-9_\-=]{180,})" + _E,
        Severity.HIGH, ("ATATT3",), "https://id.atlassian.com/manage-profile/security/api-tokens", group=1,
    ),
    Rule(
        "figma-token", "Figma access token", "Figma",
        r"(figd_[A-Za-z0-9_\-]{40,})" + _E,
        Severity.MEDIUM, ("figd_",), "https://www.figma.com/settings", group=1,
    ),
    # ---- Keys, connection strings, JWTs -----------------------------------------------------
    Rule(
        "private-key", "Private key", "Crypto",
        r"(-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----"
        r"(?:[\s\S]{40,12000}?)-----END (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----)",
        Severity.CRITICAL, ("PRIVATE KEY",), "", group=1,
        validator=lambda s: shannon_entropy(s) > 4.5 and not looks_like_placeholder(s[40:-40]),
    ),
    AnchoredRule(
        "database-url", "Database URL with password", "Database",
        r"(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|rediss?|amqps?|mssql)://"
        r"[^\s:/@\"'`\\]{1,64}:([^\s@\"'`/\\]{6,128})@[^\s\"'`<>\\]{3,}",
        Severity.HIGH, (), "", group=1, check_placeholder=True, min_entropy=2.5,
        anchors=("postgres://", "postgresql://", "mysql://", "mariadb://", "mongodb://", "mongodb+srv://",
                 "redis://", "rediss://", "amqp://", "amqps://", "mssql://"),
    ),
    JwtRule(
        "jwt", "JSON Web Token", "JWT",
        r"(eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{20,})" + _E,
        Severity.MEDIUM, ("eyJ",), "", group=1, validator=jwt_ok,
    ),
    GenericSecretRule(
        "generic-secret", "Secret assigned to a key-like name", "Generic",
        _ASSIGN_TAIL, Severity.MEDIUM, (), "", group=1, min_entropy=3.7, check_placeholder=True, boundary=False,
        validator=lambda s: not s.startswith(("sk-ant-", "ghp_", "eyJ")) and _mixed(s),
    ),
]


def _discord_id_ok(token: str) -> bool:
    """The first segment of a Discord bot token is the bot's numeric user id in base64."""
    head = token.split(".")[0]
    try:
        decoded = base64.b64decode(head + "=" * (-len(head) % 4), validate=False).decode("ascii")
    except (binascii.Error, UnicodeDecodeError):
        return False
    return decoded.isdigit() and 15 <= len(decoded) <= 22


def _mixed(value: str) -> bool:
    """Real secrets mix character classes. File paths, words and hex hashes mostly don't."""
    if "/" in value and value.count("/") >= 2:  # a path
        return False
    classes = sum(
        (any(c.islower() for c in value), any(c.isupper() for c in value), any(c.isdigit() for c in value))
    )
    return classes >= 2 and any(c.isdigit() for c in value)


def get_rules(only: Optional[Sequence[str]] = None, exclude: Optional[Sequence[str]] = None) -> list:
    """The built-in rules, optionally narrowed down by id."""
    ids = {r.id for r in BUILTIN_RULES}
    for name in list(only or []) + list(exclude or []):
        if name not in ids:
            raise ValueError(f"unknown rule {name!r}; `spillage rules` lists them")
    rules = [r for r in BUILTIN_RULES if not only or r.id in only]
    return [r for r in rules if not exclude or r.id not in exclude]
