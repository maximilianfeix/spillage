"""Fake credentials, built at runtime.

None of these strings appear literally in the repo, so GitHub push protection and other
scanners don't trip over the test suite. They are random and belong to nobody.
"""

from __future__ import annotations

import base64
import json
import random
import string
import zlib
from typing import Optional

_rng = random.Random(1337)
ALNUM = string.ascii_letters + string.digits
B62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"


def rand(n: int, alphabet: str = ALNUM) -> str:
    return "".join(_rng.choice(alphabet) for _ in range(n))


def _b62(n: int) -> str:
    out = ""
    while n:
        n, r = divmod(n, 62)
        out = B62[r] + out
    return out.rjust(6, "0")


def github(kind: str = "p", valid: bool = True) -> str:
    body = rand(30)
    check = _b62(zlib.crc32(body.encode()))
    if not valid:
        check = check[::-1] if check[::-1] != check else "000000"
    return "gh" + kind + "_" + body + check


def anthropic() -> str:
    return "sk-" + "ant-" + "api03-" + rand(93, ALNUM + "-_") + "AA"


def openai() -> str:
    return "sk-" + "proj-" + rand(24) + "T3Blbk" + "FJ" + rand(24)


def aws_key_id() -> str:
    return "AK" + "IA" + rand(16, string.ascii_uppercase + string.digits)


def aws_secret() -> str:
    return rand(40, ALNUM + "/+")


def stripe(live: bool = True) -> str:
    return "sk_" + ("live_" if live else "test_") + rand(24)


def slack() -> str:
    return "xo" + "xb-" + rand(11, string.digits) + "-" + rand(12, string.digits) + "-" + rand(24)


def google() -> str:
    return "AI" + "za" + rand(35, ALNUM + "_-")


def huggingface() -> str:
    return "hf" + "_" + rand(34, string.ascii_letters)


def npm() -> str:
    return "npm" + "_" + rand(36)


def openrouter() -> str:
    return "sk-" + "or-v1-" + rand(64, "0123456789abcdef")


def discord_bot() -> str:
    head = base64.b64encode(str(_rng.randrange(10**17, 10**18)).encode()).decode().rstrip("=")
    return head + "." + rand(6, ALNUM + "_-") + "." + rand(38, ALNUM + "_-")


def telegram() -> str:
    return str(_rng.randrange(10**8, 10**9)) + ":" + "AA" + rand(33, ALNUM + "_-")


def sendgrid() -> str:
    return "SG" + "." + rand(22) + "." + rand(43)


def jwt(payload: Optional[dict] = None) -> str:
    def enc(obj: dict) -> str:
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")

    payload = payload or {"sub": rand(8), "role": "service_role", "iat": 1700000000}
    return enc({"alg": "HS256", "typ": "JWT"}) + "." + enc(payload) + "." + rand(43, ALNUM + "_-")


def private_key() -> str:
    body = "\n".join(rand(64, ALNUM + "+/") for _ in range(12))
    kind = "OPEN" + "SSH"
    return f"-----BEGIN {kind} PRIVATE KEY-----\n{body}\n-----END {kind} PRIVATE KEY-----"


def db_password() -> str:
    return rand(20)


def db_url(password: Optional[str] = None) -> str:
    return "postgres" + "://app:" + (password or db_password()) + "@db.internal:5432/prod"


def generic_value() -> str:
    return rand(10, string.ascii_lowercase) + rand(6, string.digits) + rand(8, string.ascii_uppercase)


HEX = "0123456789abcdef"


def claude_oauth() -> str:
    return "sk-" + "ant-" + "oat01-" + rand(95, ALNUM + "-_") + "AA"


def langsmith() -> str:
    return "lsv2" + "_pt_" + rand(32, HEX) + "_" + rand(10, HEX)


def pinecone() -> str:
    return "pcsk" + "_" + rand(6) + "_" + rand(64)


def tavily() -> str:
    return "tvly" + "-dev-" + rand(32)


def firecrawl() -> str:
    return "fc" + "-" + rand(32, HEX)


def supabase_secret() -> str:
    return "sb_" + "secret_" + rand(22) + "_" + rand(8)


def resend() -> str:
    return "re" + "_" + rand(8) + "_" + rand(24)


def posthog() -> str:
    return "phx" + "_" + rand(43)


def vercel_blob() -> str:
    return "vercel_blob" + "_rw_" + rand(16) + "_" + rand(30)


def google_refresh() -> str:
    return "1//" + "0" + rand(60, ALNUM + "_-")


def doppler() -> str:
    return "dp" + ".pt." + rand(43)


def vault() -> str:
    return "hv" + "s." + rand(95, ALNUM + "_-")


def onepassword() -> str:
    return "ops" + "_eyJ" + rand(300, ALNUM + "+/")


def planetscale() -> str:
    return "pscale" + "_tkn_" + rand(43)


def brevo() -> str:
    return "xkey" + "sib-" + rand(64, HEX) + "-" + rand(16)


def sentry_user() -> str:
    return "sntry" + "u_" + rand(64, HEX)
