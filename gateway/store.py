from __future__ import annotations

import hashlib
import json
import secrets
import threading
import time
from pathlib import Path
from typing import Any

from .jcs import canonicalize

DEFAULT_STATE = {
    "agents": {},
    "employees": {},
    "actions": {},
    "data_policies": {},
    "plans": {},
    "plan_extensions": {},
    "blocks": {},
    "settings": {"risk_tolerance": "high", "system_risk_tolerances": {}},
    "revoked_tokens": {},
    "nonces": {},
    "audit": [],
}
GENESIS = "0" * 64


def _audit_hash(record: dict[str, Any]) -> str:
    body = {k: v for k, v in record.items() if k != "hash"}
    return hashlib.sha256(canonicalize(body)).hexdigest()


class Store:
    """JSON-file state for development. Every write is atomic (write + rename).

    The audit log is an append-only hash chain: each record stores the hash of the previous one,
    so modifying or deleting any record is detected by verify_audit().
    """

    def __init__(self, path: Path) -> None:
        self.path = path
        self.lock = threading.RLock()
        self.state = self._load()

    def _load(self) -> dict[str, Any]:
        fresh = json.loads(json.dumps(DEFAULT_STATE))
        if not self.path.exists():
            return fresh
        data = json.loads(self.path.read_text(encoding="utf-8"))
        state = {**fresh, **data}
        state["settings"] = {**DEFAULT_STATE["settings"], **data.get("settings", {})}
        return state

    def save(self) -> None:
        with self.lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(self.path.suffix + ".tmp")
            tmp.write_text(json.dumps(self.state, indent=2, sort_keys=True), encoding="utf-8")
            tmp.replace(self.path)

    # ---- audit (hash chain)
    def audit(self, event: dict[str, Any]) -> dict[str, Any]:
        with self.lock:
            chain = self.state["audit"]
            prev = chain[-1]["hash"] if chain else GENESIS
            record = {"id": f"aud_{secrets.token_urlsafe(12)}", "seq": len(chain) + 1, "ts": int(time.time()), "prev_hash": prev, **event}
            record["hash"] = _audit_hash(record)
            chain.append(record)
            self.save()
            return record

    def verify_audit(self) -> dict[str, Any]:
        prev = GENESIS
        for index, record in enumerate(self.state["audit"]):
            if record.get("seq") != index + 1 or record.get("prev_hash") != prev or _audit_hash(record) != record.get("hash"):
                return {"intact": False, "broken_at_seq": index + 1, "entries": len(self.state["audit"])}
            prev = record["hash"]
        return {"intact": True, "entries": len(self.state["audit"]), "head": prev}

    # ---- replay protection for signed requests
    def use_nonce(self, key: str, ttl: int) -> bool:
        with self.lock:
            now = int(time.time())
            nonces = self.state["nonces"]
            if len(nonces) > 5000:
                self.state["nonces"] = nonces = {k: v for k, v in nonces.items() if v > now}
            if key in nonces and nonces[key] > now:
                return False
            nonces[key] = now + ttl
            self.save()
            return True

    # ---- generic collections
    def put(self, collection: str, item_id: str, item: dict[str, Any]) -> dict[str, Any]:
        with self.lock:
            self.state[collection][item_id] = item
            self.save()
            return item

    def get(self, collection: str, item_id: str) -> dict[str, Any] | None:
        return self.state[collection].get(item_id)

    def list(self, collection: str) -> list[dict[str, Any]]:
        return list(self.state[collection].values())

    def delete(self, collection: str, item_id: str) -> bool:
        with self.lock:
            existed = item_id in self.state[collection]
            self.state[collection].pop(item_id, None)
            self.save()
            return existed
