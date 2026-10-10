"""Gateway-issued tokens: compact JWS signed with the gateway's Ed25519 key (no shared secrets)."""
from __future__ import annotations

import secrets
import time
from typing import Any

from .crypto import JwsError, sign_jws, verify_jws
from .jcs import sha256_hex  # re-exported for callers
from .keyring import KeyRing

TYP = {"action": "wwg-action+jwt", "data_access": "wwg-data+jwt", "policy": "wwg-policy+jwt"}
TokenError = JwsError

__all__ = ["TokenError", "issue_token", "verify_token", "sha256_hex", "TYP"]


def issue_token(keyring: KeyRing, token_type: str, claims: dict[str, Any], ttl_seconds: int, issuer: str) -> str:
    now = int(time.time())
    payload = {
        **claims,
        "iss": issuer,
        "iat": now,
        "nbf": now,
        "exp": now + ttl_seconds,
        "jti": f"tok_{secrets.token_urlsafe(18)}",
    }
    kid, key = keyring.signing_key()
    return sign_jws(key, {"kid": kid, "typ": TYP[token_type]}, payload)


def verify_token(keyring: KeyRing, token: str, expected_type: str | None, issuer: str, skew: int = 5) -> dict[str, Any]:
    """Gateway-side verification (introspection / revocation). Downstream services use wwg_verify."""
    types = [expected_type] if expected_type else ["action", "data_access"]
    last: Exception = TokenError("malformed token")
    for t in types:
        try:
            _, payload = verify_jws(token, lambda h: keyring.public_key(str(h.get("kid"))), TYP[t])
            break
        except TokenError as exc:
            last = exc
    else:
        raise last
    now = int(time.time())
    if payload.get("iss") != issuer:
        raise TokenError("wrong issuer")
    if not isinstance(payload.get("exp"), int) or now >= payload["exp"] + skew:
        raise TokenError("expired token")
    if isinstance(payload.get("nbf"), int) and now + skew < payload["nbf"]:
        raise TokenError("token not yet valid")
    payload["typ"] = t
    return payload
