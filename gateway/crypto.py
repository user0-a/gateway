"""Ed25519 keys, JWK thumbprints and compact JWS (alg=EdDSA only)."""
from __future__ import annotations

import base64
import hashlib
import json
from typing import Any, Callable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .jcs import canonicalize

ALG = "EdDSA"


class JwsError(ValueError):
    pass


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def unb64url(value: str) -> bytes:
    if not isinstance(value, str) or any(c in value for c in "+/="):
        raise JwsError("invalid base64url")
    try:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except Exception as exc:  # binascii.Error
        raise JwsError("invalid base64url") from exc


def public_raw(key: Ed25519PublicKey) -> bytes:
    return key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def public_jwk(key: Ed25519PublicKey, kid: str | None = None) -> dict[str, str]:
    jwk = {"kty": "OKP", "crv": "Ed25519", "x": b64url(public_raw(key))}
    if kid:
        jwk["kid"] = kid
    return jwk


def public_key_from_jwk(jwk: dict[str, Any]) -> Ed25519PublicKey:
    if not isinstance(jwk, dict) or jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
        raise JwsError("unsupported key type")
    raw = unb64url(jwk.get("x", ""))
    if len(raw) != 32:
        raise JwsError("invalid Ed25519 public key")
    return Ed25519PublicKey.from_public_bytes(raw)


def public_key_from_x(x: str) -> Ed25519PublicKey:
    return public_key_from_jwk({"kty": "OKP", "crv": "Ed25519", "x": x})


def jwk_thumbprint(jwk: dict[str, Any]) -> str:
    """RFC 7638 thumbprint of an Ed25519 JWK (members crv, kty, x)."""
    required = {"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"]}
    return b64url(hashlib.sha256(canonicalize(required)).digest())


def sign_jws(private_key: Ed25519PrivateKey, header: dict[str, Any], payload: dict[str, Any]) -> str:
    header = {**header, "alg": ALG}
    signing_input = b64url(canonicalize(header)) + "." + b64url(canonicalize(payload))
    signature = private_key.sign(signing_input.encode("ascii"))
    return signing_input + "." + b64url(signature)


def decode_unverified(token: str) -> tuple[dict[str, Any], dict[str, Any]]:
    if not isinstance(token, str) or token.count(".") != 2 or len(token) > 16384:
        raise JwsError("malformed token")
    h, p, _ = token.split(".")
    try:
        header = json.loads(unb64url(h))
        payload = json.loads(unb64url(p))
    except (ValueError, UnicodeDecodeError) as exc:
        raise JwsError("malformed token") from exc
    if not isinstance(header, dict) or not isinstance(payload, dict):
        raise JwsError("malformed token")
    return header, payload


def verify_jws(token: str, key_for_header: Callable[[dict[str, Any]], Ed25519PublicKey], expected_typ: str) -> tuple[dict[str, Any], dict[str, Any]]:
    header, payload = decode_unverified(token)
    if header.get("alg") != ALG:
        raise JwsError("unsupported alg")
    if header.get("typ") != expected_typ:
        raise JwsError("wrong token type")
    if "crit" in header:
        raise JwsError("unsupported critical header")
    key = key_for_header(header)
    h, p, s = token.split(".")
    try:
        key.verify(unb64url(s), f"{h}.{p}".encode("ascii"))
    except InvalidSignature as exc:
        raise JwsError("bad signature") from exc
    return header, payload


def request_signing_payload(method: str, path: str, ts: int, nonce: str, body: bytes) -> bytes:
    """What an agent/employee signs to authenticate an HTTP request to the gateway."""
    return canonicalize({"m": method.upper(), "p": path, "ts": ts, "n": nonce, "bh": b64url(hashlib.sha256(body).digest())})
