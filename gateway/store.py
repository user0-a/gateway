from __future__ import annotations

import json
import secrets
import threading
import time
from pathlib import Path
from typing import Any


DEFAULT_STATE = {
    "agents": {},
    "actions": {},
    "data_policies": {},
    "plans": {},
    "plan_extensions": {},
    "blocks": {},
    "settings": {"risk_tolerance": "high", "system_risk_tolerances": {}},
    "revoked_tokens": {},
    "audit": [],
}


class Store:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.lock = threading.RLock()
        self.state = self._load()

    def _load(self) -> dict[str, Any]:
        if not self.path.exists():
            return json.loads(json.dumps(DEFAULT_STATE))
        data = json.loads(self.path.read_text(encoding="utf-8"))
        state = {**json.loads(json.dumps(DEFAULT_STATE)), **data}
        state["settings"] = {**DEFAULT_STATE["settings"], **data.get("settings", {})}
        return state

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp.write_text(json.dumps(self.state, indent=2, sort_keys=True), encoding="utf-8")
        tmp.replace(self.path)

    def audit(self, event: dict[str, Any]) -> dict[str, Any]:
        with self.lock:
            record = {"id": f"aud_{secrets.token_urlsafe(12)}", "ts": int(time.time()), **event}
            self.state["audit"].append(record)
            self.state["audit"] = self.state["audit"][-1000:]
            self.save()
            return record

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
