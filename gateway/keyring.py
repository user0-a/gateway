"""Gateway signing keys with rotation. Private keys live on disk (PEM, 0600), never in the repo."""
from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .crypto import JwsError, jwk_thumbprint, public_jwk


class KeyRing:
    """keys.json lists keys with status: active (signs + verifies), retiring (verifies only)."""

    def __init__(self, directory: Path) -> None:
        self.dir = directory
        self.lock = threading.RLock()
        self.dir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.dir, 0o700)
        except OSError:
            pass
        self.meta_path = self.dir / "keys.json"
        self.private: dict[str, Ed25519PrivateKey] = {}
        self.meta: list[dict[str, Any]] = []
        self._load()
        if not self.active_kid():
            self.rotate()

    def _load(self) -> None:
        if self.meta_path.exists():
            self.meta = json.loads(self.meta_path.read_text(encoding="utf-8"))
        for entry in self.meta:
            pem = (self.dir / f"{entry['kid']}.pem").read_bytes()
            key = serialization.load_pem_private_key(pem, password=None)
            if not isinstance(key, Ed25519PrivateKey):
                raise JwsError("gateway key must be Ed25519")
            self.private[entry["kid"]] = key

    def _save(self) -> None:
        tmp = self.meta_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.meta, indent=2), encoding="utf-8")
        tmp.replace(self.meta_path)

    def active_kid(self) -> str | None:
        active = [m for m in self.meta if m["status"] == "active"]
        return active[-1]["kid"] if active else None

    def rotate(self) -> str:
        with self.lock:
            key = Ed25519PrivateKey.generate()
            kid = jwk_thumbprint(public_jwk(key.public_key()))[:16]
            path = self.dir / f"{kid}.pem"
            path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass
            for entry in self.meta:
                if entry["status"] == "active":
                    entry["status"] = "retiring"
            self.meta.append({"kid": kid, "status": "active", "created_at": int(time.time())})
            self.private[kid] = key
            self._save()
            return kid

    def retire(self, kid: str) -> bool:
        with self.lock:
            entry = next((m for m in self.meta if m["kid"] == kid), None)
            if entry is None or entry["status"] == "active":
                return False
            self.meta = [m for m in self.meta if m["kid"] != kid]
            self.private.pop(kid, None)
            (self.dir / f"{kid}.pem").unlink(missing_ok=True)
            self._save()
            return True

    def signing_key(self) -> tuple[str, Ed25519PrivateKey]:
        kid = self.active_kid()
        assert kid is not None
        return kid, self.private[kid]

    def public_key(self, kid: str) -> Ed25519PublicKey:
        if kid not in self.private:
            raise JwsError("unknown kid")
        return self.private[kid].public_key()

    def jwks(self) -> dict[str, Any]:
        return {"keys": [{**public_jwk(self.private[m["kid"]].public_key(), m["kid"]), "use": "sig", "alg": "EdDSA"} for m in self.meta]}
