from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from typing import Any


class TokenError(ValueError):
    pass


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _unb64url(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_hex(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def issue_token(secret: str, token_type: str, claims: dict[str, Any], ttl_seconds: int) -> str:
    now = int(time.time())
    payload = {
        "typ": token_type,
        "iat": now,
        "exp": now + ttl_seconds,
        "jti": f"tok_{secrets.token_urlsafe(18)}",
        **claims,
    }
    encoded_payload = _b64url(canonical_json(payload))
    signature = hmac.new(secret.encode("utf-8"), encoded_payload.encode("ascii"), hashlib.sha256).digest()
    return f"{encoded_payload}.{_b64url(signature)}"


def verify_token(secret: str, token: str, expected_type: str | None = None) -> dict[str, Any]:
    if not isinstance(token, str) or token.count(".") != 1:
        raise TokenError("malformed token")
    encoded_payload, encoded_signature = token.split(".", 1)
    expected = hmac.new(secret.encode("utf-8"), encoded_payload.encode("ascii"), hashlib.sha256).digest()
    try:
        signature = _unb64url(encoded_signature)
        payload = json.loads(_unb64url(encoded_payload))
    except Exception as exc:
        raise TokenError("malformed token") from exc
    if not hmac.compare_digest(signature, expected):
        raise TokenError("bad signature")
    if not isinstance(payload, dict):
        raise TokenError("bad payload")
    if expected_type is not None and payload.get("typ") != expected_type:
        raise TokenError("wrong token type")
    if not isinstance(payload.get("exp"), int) or int(time.time()) >= payload["exp"]:
        raise TokenError("expired token")
    return payload
