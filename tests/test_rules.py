from __future__ import annotations

import json

import fakes
import pytest

from spillage.models import Severity
from spillage.rules import (
    BUILTIN_RULES,
    get_rules,
    github_checksum_ok,
    jwt_ok,
    left_boundary_ok,
    looks_like_placeholder,
    shannon_entropy,
)
from spillage.scanner import find_in_text, scan_text


def ids(text: str) -> list:
    return [rule.id for rule, _ in find_in_text(text, BUILTIN_RULES)]


def secrets(text: str) -> list:
    return [m.secret for _, m in find_in_text(text, BUILTIN_RULES)]


POSITIVES = [
    ("docker-org-token", fakes.docker_oat),
    ("vercel-token", fakes.vercel),
    ("vercel-token", lambda: fakes.vercel("k")),
    ("cloudflare-api-token", fakes.cloudflare),
    ("cloudflare-api-token", lambda: fakes.cloudflare("k")),
    ("supabase-access-token", fakes.supabase_access),
    ("brave-search-api-key", fakes.brave),
    ("aws-bedrock-api-key", fakes.bedrock),
    ("neon-api-key", fakes.neon),
    ("together-api-key", fakes.together),
    ("cerebras-api-key", fakes.cerebras),
    ("nvidia-api-key", fakes.nvidia),
    ("langfuse-secret-key", fakes.langfuse),
    ("wandb-api-key", fakes.wandb),
    ("gitlab-deploy-token", fakes.gitlab_deploy),
    ("gitlab-deploy-token", lambda: fakes.gitlab_deploy("rt")),
    ("gitlab-token", fakes.gitlab_routable),
    ("github-token", fakes.github_refresh),
    ("slack-token", fakes.slack_refresh),
    ("github-token", lambda: fakes.github("p")),
    ("github-token", lambda: fakes.github("o")),
    ("github-token", lambda: fakes.github("s")),
    ("anthropic-api-key", fakes.anthropic),
    ("openai-api-key", fakes.openai),
    ("openrouter-api-key", fakes.openrouter),
    ("aws-access-key-id", fakes.aws_key_id),
    ("stripe-secret-key", fakes.stripe),
    ("slack-token", fakes.slack),
    ("google-api-key", fakes.google),
    ("huggingface-token", fakes.huggingface),
    ("npm-token", fakes.npm),
    ("discord-bot-token", fakes.discord_bot),
    ("telegram-bot-token", fakes.telegram),
    ("sendgrid-api-key", fakes.sendgrid),
    ("jwt", fakes.jwt),
    ("private-key", fakes.private_key),
    ("claude-oauth-token", fakes.claude_oauth),
    ("langsmith-api-key", fakes.langsmith),
    ("pinecone-api-key", fakes.pinecone),
    ("tavily-api-key", fakes.tavily),
    ("firecrawl-api-key", fakes.firecrawl),
    ("supabase-secret-key", fakes.supabase_secret),
    ("resend-api-key", fakes.resend),
    ("posthog-personal-key", fakes.posthog),
    ("vercel-blob-token", fakes.vercel_blob),
    ("google-oauth-refresh-token", fakes.google_refresh),
    ("doppler-token", fakes.doppler),
    ("vault-token", fakes.vault),
    ("1password-service-account", fakes.onepassword),
    ("planetscale-token", fakes.planetscale),
    ("brevo-api-key", fakes.brevo),
    ("docker-pat", fakes.docker_pat),
    ("tailscale-key", fakes.tailscale),
    ("tailscale-key", lambda: fakes.tailscale("api")),
    ("flyio-token", fakes.flyio),
    ("netlify-token", fakes.netlify),
    ("render-api-key", fakes.render_key),
    ("heroku-api-key", fakes.heroku),
    ("pulumi-token", fakes.pulumi),
    ("age-secret-key", fakes.age_key),
    ("rubygems-token", fakes.rubygems),
    ("bitbucket-app-password", fakes.bitbucket),
    ("newrelic-user-key", fakes.newrelic),
    ("mapbox-secret-token", fakes.mapbox),
    ("airtable-token", fakes.airtable),
    ("elevenlabs-api-key", fakes.elevenlabs),
    ("e2b-api-key", fakes.e2b),
    ("square-token", fakes.square),
    ("square-token", lambda: fakes.square("csp")),
    ("stripe-webhook-secret", fakes.stripe_webhook),
    ("slack-app-token", fakes.slack_app),
    ("huggingface-org-token", fakes.huggingface_org),
    ("clojars-token", fakes.clojars),
    ("duffel-token", fakes.duffel),
    ("easypost-api-key", fakes.easypost),
    ("easypost-api-key", lambda: fakes.easypost(test=True)),
    ("frameio-token", fakes.frameio),
    ("infracost-token", fakes.infracost),
    ("prefect-token", fakes.prefect),
    ("readme-api-key", fakes.readme_key),
    ("scalingo-token", fakes.scalingo),
    ("cloudflare-origin-ca-key", fakes.cloudflare_origin_ca),
    ("gitlab-agent-token", fakes.gitlab_agent),
]


@pytest.mark.parametrize("rule_id,make", POSITIVES, ids=[p[0] + str(i) for i, p in enumerate(POSITIVES)])
@pytest.mark.parametrize("wrap", ["{}", "export KEY={}", "'{}'", '"token": "{}",', "see {} here", "({})"])
def test_detects_each_provider_in_context(rule_id, make, wrap):
    secret = make()
    hits = find_in_text(wrap.format(secret), BUILTIN_RULES)
    assert [(r.id, m.secret) for r, m in hits] == [(rule_id, secret)]


def test_match_offsets_point_at_the_secret():
    secret = fakes.github()
    text = f"xx {secret} yy"
    (_, m), = find_in_text(text, BUILTIN_RULES)
    assert text[m.start : m.end] == secret


def test_github_checksum_filters_lookalikes():
    assert github_checksum_ok(fakes.github())
    assert not github_checksum_ok(fakes.github(valid=False))
    assert ids(fakes.github(valid=False)) == []


def test_aws_example_key_is_ignored():
    assert ids("AKIA" + "IOSFODNN7" + "EXAMPLE") == []


def test_aws_secret_needs_its_name():
    value = fakes.aws_secret()
    assert "aws-secret-access-key" in ids(f"aws_secret_access_key = {value}")
    assert "aws-secret-access-key" in ids(f'AWS_SECRET_ACCESS_KEY="{value}"')
    assert "aws-secret-access-key" not in ids(value)


def test_stripe_test_keys_are_low_severity():
    (live,) = scan_text(fakes.stripe(live=True))
    (test,) = scan_text(fakes.stripe(live=False))
    assert live.severity is Severity.CRITICAL
    assert test.severity is Severity.LOW


def test_supabase_anon_jwt_is_low():
    (f,) = scan_text(fakes.jwt({"role": "anon", "iss": "supabase"}))
    assert f.severity is Severity.LOW
    (g,) = scan_text(fakes.jwt())
    assert g.severity is Severity.MEDIUM


def test_jwt_must_decode():
    token = fakes.jwt()
    assert jwt_ok(token)
    _, payload, sig = token.split(".")
    assert not jwt_ok("eyJ" + "notjson" * 3 + "." + payload + "." + sig)


def test_database_url_reports_only_the_password():
    pw = fakes.db_password()
    assert secrets(fakes.db_url(pw)) == [pw]


@pytest.mark.parametrize("url", [
    "postgres://user:password@localhost/db",
    "postgres://user:${DB_PASSWORD}@localhost/db",
    "mysql://root:changeme@127.0.0.1/app",
    "redis://:xxxxxxxx@cache:6379",
    "postgres://localhost:5432/db",
])
def test_database_url_placeholders_are_skipped(url):
    assert ids(url) == []


@pytest.mark.parametrize("text", [
    'API_KEY="{v}"',
    "api_key: {v}",
    "export OPENWEATHER_API_KEY={v}",
    '"client_secret": "{v}"',
    "clientSecret = '{v}'",
    "password={v}",
    "Authorization: Bearer {v}",
    'db_password => "{v}"',
])
def test_generic_assignments(text):
    value = fakes.generic_value()
    assert secrets(text.format(v=value)) == [value]


@pytest.mark.parametrize("text", [
    "token = {v}".replace("{v}", "a" * 30),
    "monkey = X7fk29dkLmq83kdPq0zAa",
    "Unable to reserve cache with key node-cache-Linux-x64-npm-8f7d9e6c5b4a",
    "max_tokens: 8192",
    "api_key = YOUR_API_KEY_HERE_1234",
    "api_key = <your-api-key-goes-here>",
    'password = "${{ secrets.DB_PASSWORD }}"',
    "secret = os.environ['SECRET_KEY']",
    "token: /usr/local/lib/python3.12/site-packages/foo",
    "commit 3f2a9c1e5b7d4f8a0c6e2b9d1f3a5c7e9b0d2f4a",
    "id 123e4567-e89b-12d3-a456-426614174000",
    "sk-ant-" + "api03-short",
    "re_compile_pattern_for_the_parser",
    "sb_publishable_" + "abcdefghijklmnopqrstuvwxyz0123",
    "see https://example.com/fc-0000000000000000000000000000000",
])
def test_things_that_are_not_secrets(text):
    assert ids(text) == []


def test_specific_rules_win_over_generic():
    gh = fakes.github()
    assert ids(f"GITHUB_TOKEN={gh}") == ["github-token"]


def test_token_inside_a_longer_token_is_not_matched():
    assert ids("x" + fakes.github()) == []


def test_json_escaped_newline_counts_as_a_boundary():
    gh = fakes.github()
    raw = json.dumps({"text": f"line one\n{gh}"})
    assert ids(raw) == ["github-token"]


def test_left_boundary():
    assert left_boundary_ok("abc", 0)
    assert left_boundary_ok(" abc", 1)
    assert not left_boundary_ok("xabc", 1)
    assert left_boundary_ok("\\nabc", 2)


def test_private_key_inside_json_is_found_escaped():
    pk = fakes.private_key()
    raw = json.dumps({"content": pk})
    (hit,) = secrets(raw)
    assert json.loads('"' + hit + '"') == pk


def test_private_key_placeholder_is_skipped():
    fake = "-----BEGIN RSA PRIVATE KEY-----\n" + "...\n" * 20 + "-----END RSA PRIVATE KEY-----"
    assert ids(fake) == []


def test_multiple_secrets_come_back_in_text_order():
    a, b, c = fakes.stripe(), fakes.github(), fakes.npm()
    assert secrets(f"{a} and {b} and {c}") == [a, b, c]


def test_placeholders():
    assert looks_like_placeholder("your_api_key_here")
    assert looks_like_placeholder("xxxxxxxxxxxxxxxx")
    assert looks_like_placeholder("${SECRET}")
    assert not looks_like_placeholder(fakes.generic_value())


def test_entropy():
    assert shannon_entropy("") == 0
    assert shannon_entropy("aaaa") == 0
    assert shannon_entropy(fakes.rand(64)) > 4.5


def test_rule_ids_are_unique_and_described():
    seen = set()
    for rule in BUILTIN_RULES:
        assert rule.id not in seen
        seen.add(rule.id)
        assert rule.name and rule.provider
        assert rule.rotate_url == "" or rule.rotate_url.startswith("https://")


def test_get_rules_filters_and_validates():
    assert [r.id for r in get_rules(only=["jwt"])] == ["jwt"]
    assert "jwt" not in [r.id for r in get_rules(exclude=["jwt"])]
    with pytest.raises(ValueError, match="unknown rule"):
        get_rules(only=["nope"])


def test_azure_storage_key_is_found_in_a_connection_string():
    key = fakes.azure_storage_key()
    conn = f"DefaultEndpointsProtocol=https;AccountName=shop;AccountKey={key};EndpointSuffix=core.windows.net"
    assert [(r.id, m.secret) for r, m in find_in_text(conn, BUILTIN_RULES)] == [("azure-storage-key", key)]
    assert "azure-storage-key" not in ids(key)  # 88 characters of base64 on their own could be anything
    assert ids("AccountKey=<your-storage-key>") == []


@pytest.mark.parametrize("text", [
    "rnd_seed_for_the_shuffle_function_1",  # a variable name, not a Render key
    "rnd_" + "a" * 32,  # no entropy
    "dckr_pat_short",
    "tskey-auth-example",
    "sk_" + "0" * 48,  # ElevenLabs shape, but a placeholder
    "pul-" + "0123456789abcdef",  # too short for Pulumi
    "whsec_your_webhook_secret_goes_here_ok",
    "AGE-SECRET-KEY-1" + "Q" * 20,
    "pattern.matches(value)",  # Airtable tokens start with pat
    "sk.eyJ.short",
    "NRAK-TOOSHORT",
    "nfp_netlify",
])
def test_new_token_lookalikes_are_not_reported(text):
    assert ids(text) == []


def test_new_tokens_inside_longer_tokens_are_not_matched():
    assert ids("x" + fakes.netlify()) == []
    assert ids(fakes.pulumi() + "ab") == []
    assert ids(fakes.e2b() + "0") == []


def test_shapes_that_the_first_version_of_these_rules_missed():
    # each of these is valid by the gitleaks rule set and slipped through before
    slack = "xapp" + "-1-A" + fakes.rand(9, "ABCDEFGHJK0123456789") + "-" + fakes.rand(12, "0123456789") + "-" \
        + fakes.rand(40, "abcdefghijklmnopqrstuvwxyz0123456789")
    square = "sq0" + "atp-" + fakes.rand(48)
    tailscale = "tskey" + "-webhook-" + fakes.rand(12) + "CNTRL-" + fakes.rand(32)
    bitbucket = "AT" + "BB" + fakes.rand(28) + "=" + fakes.rand(7, "0123456789ABCDEF")
    assert ids(slack) == ["slack-app-token"]
    assert ids(square) == ["square-token"]
    assert ids(tailscale) == ["tailscale-key"]
    assert ids(bitbucket) == ["bitbucket-app-password"]


@pytest.mark.parametrize("text", [
    "ico-favicon-16x16-and-32x32-in-one-file",  # an icon name, not an Infracost token
    "pnu_" + "a" * 36,
    "tk-us-east-1",
    "v1.0-rc1",
    "rdme_docs",
    "EZAKshort",
    "CLOJARS_USERNAME",
    "fio-u-",
    "api_org_name",
    "duffel_test_key",
    "glagent-token",
])
def test_lookalikes_of_the_gitleaks_formats(text):
    assert ids(text) == []


def test_no_rule_gets_slow_on_text_made_to_hurt_it():
    """A prompt is scanned by the hook before it is sent, so no input may make a rule crawl.
    Each rule gets its own keywords and prefixes, repeated: the JWT rule took 4x longer for
    every doubling of "eyJeyJeyJ…" before it stopped starting over at every `eyJ`."""
    import time

    size = 200_000
    slow = []
    for rule in get_rules():
        starts = {k for k in rule.keywords if k} or {"=", ":", "."}
        for start in starts:
            for text in (start * (size // len(start)), (start + "a") * (size // (len(start) + 1)),
                         (start + " ") * (size // (len(start) + 1))):
                began = time.perf_counter()
                list(rule.find(text))
                taken = time.perf_counter() - began
                if taken > 2.0:
                    slow.append((rule.id, start, round(taken, 2)))
    assert slow == []


def test_a_key_printed_in_colour_is_found():
    """Tools colour their output; the escape code ends in a letter right before the key."""
    key = fakes.github()
    for before in ("\x1b[32m", "\x1b[1;31m", "\\u001b[32m", "\\x1b[0m", "\\033[36m"):
        assert secrets(f"TOKEN {before}{key}\x1b[0m") == [key], before
    assert secrets(f"atom{key}") == []  # an ordinary letter before it is still part of a longer word


def test_the_whole_token_is_reported_so_the_whole_token_is_scrubbed():
    routable, refresh = fakes.gitlab_routable(), fakes.slack_refresh()
    assert secrets(f"GITLAB={routable} SLACK={refresh}") == [routable, refresh]


@pytest.mark.parametrize("text", [
    "BSAFETY_CHECK_FOR_ALL_THE_MODULES_27", "vcp_" + "a" * 56, "sbp_" + "0" * 40, "csk-" + "a" * 48,
    "ABSK" + "A" * 140, "see the ghr_" + "a" * 60 + " placeholder", "napi_" + "x" * 64,
])
def test_lookalikes_of_the_newer_formats(text):
    assert ids(text) == []


def test_a_slack_token_ends_where_the_url_encoding_starts():
    token = fakes.slack()
    assert secrets(f"token={token}%26channel%3DC0123%26text%3Dhi") == [token]
