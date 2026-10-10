from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk" / "python"))

from wwg_sdk import AgentClient, GatewayVerifier, MemoryReplayStore, canonicalize  # noqa: E402

from gateway.app import ISSUER, create_app  # noqa: E402
from gateway.store import Store  # noqa: E402

ADMIN = {"x-admin-key": "dev-admin-key"}


def action(id_: str, **overrides: Any) -> dict[str, Any]:
    base = {
        "id": id_, "description": "", "service": "mini-bank", "operation": id_, "ttl_seconds": 60,
        "required_fields": [], "max_amount": None, "allowed_roles": [], "base_risk": "low",
        "risk_rules": [], "requires_plan": False,
    }
    return {**base, **overrides}


class World:
    """A gateway with one signed agent, one legacy agent and two employees."""

    def __init__(self, tmp_path: Path) -> None:
        self.store = Store(tmp_path / "state.json")
        self.app = create_app(self.store)
        self.http = TestClient(self.app)
        s = self.store
        s.put("actions", "transfer.create", action("transfer.create", required_fields=["from_account", "to_account", "amount"], max_amount=1000, allowed_roles=["operator", "admin"], base_risk="medium", risk_rules=[{"field": "amount", "gte": 500, "risk": "high"}]))
        s.put("actions", "users.select", action("users.select", required_fields=["limit"], risk_rules=[{"field": "limit", "gte": 100, "risk": "medium"}]))
        s.put("actions", "records.delete", action("records.delete", required_fields=["record_count"], allowed_roles=["admin"], base_risk="medium", risk_rules=[{"field": "record_count", "gte": 100, "risk": "high"}]))
        s.put("actions", "customer.read", action("customer.read", required_fields=["customer_id"], allowed_roles=["operator", "admin"], base_risk="medium"))
        s.put("data_policies", "accounts", {"id": "accounts", "description": "", "tables": ["accounts"], "columns": {"accounts": ["id", "owner", "balance"]}, "row_filters": {"accounts": {"owner": "subject.customer_name"}}, "ttl_seconds": 300})

        self.agent_key = AgentClient.generate_key()
        self.agent = AgentClient("agent-1", self.agent_key)
        self.other_agent = AgentClient("agent-2", AgentClient.generate_key())
        for client in (self.agent, self.other_agent):
            s.put("agents", client.agent_id, {"id": client.agent_id, "name": client.agent_id, "public_key": client.jwk["x"], "active": True,
                                             "allowed_actions": ["transfer.create", "users.select", "records.delete", "customer.read"], "allowed_data_policies": ["accounts"]})
        r = self.http.post("/admin/agents", headers=ADMIN, json={"id": "legacy", "name": "Legacy", "api_key": "legacy-agent-key-123456", "allowed_actions": ["users.select", "transfer.create"]})
        assert r.status_code == 200, r.text

        self.anna = AgentClient("emp-anna", AgentClient.generate_key())     # operator
        self.marek = AgentClient("emp-marek", AgentClient.generate_key())   # admin
        for emp, role in ((self.anna, "operator"), (self.marek, "admin")):
            r = self.http.post("/admin/employees", headers=ADMIN, json={"id": emp.agent_id, "name": emp.agent_id, "role": role, "public_key": emp.jwk["x"], "attributes": {"customer_name": "Ala"}})
            assert r.status_code == 200, r.text

    # signed calls ---------------------------------------------------------
    def agent_post(self, path: str, payload: dict[str, Any], client: AgentClient | None = None, headers: dict[str, str] | None = None):
        client = client or self.agent
        body = canonicalize(payload)
        h = {"content-type": "application/json", **client.signed_headers("POST", path, body), **(headers or {})}
        return self.http.post(path, content=body, headers=h)

    def employee_post(self, path: str, payload: dict[str, Any], employee: AgentClient):
        body = canonicalize(payload)
        h = {"content-type": "application/json", **employee.signed_headers("POST", path, body, prefix="x-employee")}
        return self.http.post(path, content=body, headers=h)

    # flows ----------------------------------------------------------------
    def approved_plan(self, plan_id: str = "plan-1", employee: AgentClient | None = None, steps: list[dict[str, Any]] | None = None) -> dict[str, Any]:
        employee = employee or self.anna
        steps = steps or [
            {"id": "s1", "action": "customer.read", "params": {"customer_id": "c-1"}},
            {"id": "s2", "action": "transfer.create", "params": {"from_account": 1, "to_account": 2, "amount": "100.00"}},
        ]
        r = self.agent_post("/v1/plans", {"plan_id": plan_id, "goal": "Handle invoice INV-847", "subject": {"employee_id": employee.agent_id}, "steps": steps})
        assert r.status_code == 200, r.text
        created = r.json()
        assert created["decision"] == "requires_approval", created
        a = self.employee_post(f"/v1/plans/{plan_id}/approval", {"decision": "approve", "plan_hash": created["plan_hash"]}, employee)
        assert a.status_code == 200, a.text
        return created

    def step_token(self, plan_id: str, step: dict[str, Any], data_policy: str | None = None) -> dict[str, Any]:
        r = self.agent_post("/v1/authorize", {"action": step["action"], "params": step["params"], "plan_id": plan_id, "step_id": step["id"], "data_policy": data_policy})
        assert r.status_code == 200, r.text
        return r.json()

    def verifier(self, **kwargs: Any) -> GatewayVerifier:
        def fetch(url: str) -> dict[str, Any]:
            path = url.replace("http://gateway", "")
            r = self.http.get(path)
            r.raise_for_status()
            return r.json()

        return GatewayVerifier(gateway_url="http://gateway", issuer=ISSUER, audience="mini-bank", replay_store=MemoryReplayStore(), fetch_json=fetch, **kwargs)
