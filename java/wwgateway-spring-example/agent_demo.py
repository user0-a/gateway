"""Demo agent -> gateway -> Spring payments service (wwgateway-spring-example).

Needs: gateway on :8001 after `python scripts/bootstrap.py` (development mode, admin key dev-admin-key),
and this example on :8002. Run from the gateway repository root:

    python java/wwgateway-spring-example/agent_demo.py --attacks
"""
from __future__ import annotations

import argparse
import os
import secrets
import sys
from pathlib import Path
from typing import Any

import httpx

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "sdk" / "python"))
from wwg_sdk import AgentClient, canonicalize  # noqa: E402

KEYS = Path(os.environ.get("WWG_DEMO_KEYS", ROOT / ".demo_keys"))
ACTION = {
    "id": "payment.create",
    "description": "Create a payment in core-payments (Spring example)",
    "service": "core-payments",          # becomes the token "aud"; must equal wwgateway.audience
    "operation": "payment.create",
    "ttl_seconds": 30,
    "required_fields": ["from_account", "to_account", "amount"],
    "max_amount": 1000,
    "allowed_roles": ["operator", "admin"],
    "base_risk": "medium",
    "risk_rules": [],
    "requires_plan": True,
}


def load(name: str) -> AgentClient:
    return AgentClient(name, AgentClient.load_key((KEYS / f"{name}.pem").read_bytes()))


def signed_post(http: httpx.Client, client: AgentClient, path: str, payload: dict[str, Any], prefix: str = "x-agent") -> httpx.Response:
    body = canonicalize(payload)
    return http.post(path, content=body, headers={"content-type": "application/json", **client.signed_headers("POST", path, body, prefix=prefix)})


def show(label: str, response: httpx.Response) -> dict[str, Any]:
    data = response.json()
    print(f"\n[{response.status_code}] {label}")
    detail = data.get("detail", data)
    print(f"    {detail if not isinstance(detail, dict) else {k: v for k, v in detail.items() if 'token' not in k}}")
    return data


def register(gw: httpx.Client, admin_key: str) -> None:
    """One-time admin setup: the action and the agent's permission to request it."""
    h = {"x-admin-key": admin_key}
    gw.post("/admin/actions", json=ACTION, headers=h).raise_for_status()
    agents = gw.get("/admin/agents", headers=h).raise_for_status().json()["agents"]
    agent = next(a for a in agents if a["id"] == "agent-demo")
    if ACTION["id"] not in agent["allowed_actions"]:
        agent["allowed_actions"].append(ACTION["id"])
        fields = ("id", "name", "public_key", "active", "allowed_actions", "allowed_data_policies")
        gw.post("/admin/agents", json={k: agent[k] for k in fields}, headers=h).raise_for_status()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--gateway", default="http://127.0.0.1:8001")
    parser.add_argument("--payments", default="http://127.0.0.1:8002")
    parser.add_argument("--admin-key", default=os.environ.get("GATEWAY_ADMIN_KEY", "dev-admin-key"))
    parser.add_argument("--amount", default="120.00")
    parser.add_argument("--attacks", action="store_true")
    args = parser.parse_args()

    agent, employee = load("agent-demo"), load("emp-operator")
    gw = httpx.Client(base_url=args.gateway, timeout=10)
    payments = httpx.Client(base_url=args.payments, timeout=10)
    register(gw, args.admin_key)

    params = {"from_account": "PL61109010140000071219812874", "to_account": "DE89370400440532013000",
              "amount": args.amount, "title": "Invoice INV-847"}
    plan_id = "plan-" + secrets.token_hex(4)
    plan = show("Agent proposes a plan", signed_post(gw, agent, "/v1/plans", {
        "plan_id": plan_id, "goal": "Pay invoice INV-847", "subject": {"employee_id": "emp-operator"},
        "steps": [{"id": "s1", "action": "payment.create", "params": params}],
    }))
    show("Employee approves the exact plan hash", signed_post(
        gw, employee, f"/v1/plans/{plan_id}/approval", {"decision": "approve", "plan_hash": plan["plan_hash"]}, prefix="x-employee"))
    issued = show("Agent gets the token for step s1", signed_post(
        gw, agent, "/v1/authorize", {"action": "payment.create", "params": params, "plan_id": plan_id, "step_id": "s1"}))
    token = issued["action_token"]

    def call(body: dict[str, Any], proof_key: AgentClient = agent) -> httpx.Response:
        url = f"{args.payments}/payments"
        return payments.post("/payments", json=body, headers={"Authorization": f"GatewayAction {token}", "WWG-Proof": proof_key.proof("POST", url, token)})

    show("Spring payments service executes the payment", call(params))
    if args.attacks:
        show("ATTACK: replay the same token", call(params))
        show("ATTACK: stolen token without the agent key", call(params, AgentClient("agent-demo", AgentClient.generate_key())))
        show("ATTACK: change the amount after authorization", call({**params, "amount": "999.00"}))


if __name__ == "__main__":
    main()
