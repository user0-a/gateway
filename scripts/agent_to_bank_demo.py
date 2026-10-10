"""End-to-end demo: employee-approved plan -> per-step token -> bank call with proof of possession.

Run after `make bootstrap`, with the gateway on :8001 and mini-bank on :8000 in gateway mode.
Add --attacks to replay the token, use it without the agent key, and change parameters.
"""
from __future__ import annotations

import argparse
import secrets
import sys
from pathlib import Path
from typing import Any

import httpx

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk" / "python"))
from wwg_sdk import AgentClient, canonicalize  # noqa: E402

import os  # noqa: E402

KEYS = Path(os.environ.get("WWG_DEMO_KEYS", ROOT / ".demo_keys"))


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


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gateway", default="http://127.0.0.1:8001")
    parser.add_argument("--bank", default="http://127.0.0.1:8000")
    parser.add_argument("--name", default="Jane Agent")
    parser.add_argument("--email", default="jane.agent@example.com")
    parser.add_argument("--initial-balance", default="25.00")
    parser.add_argument("--attacks", action="store_true")
    args = parser.parse_args()

    agent, employee = load("agent-demo"), load("emp-admin")
    gw = httpx.Client(base_url=args.gateway, timeout=10)
    bank = httpx.Client(base_url=args.bank, timeout=10)
    params = {"email": args.email, "name": args.name, "initial_balance": args.initial_balance}
    plan_id = "plan-" + secrets.token_hex(4)

    plan = show("Agent proposes a plan (no tokens yet)", signed_post(gw, agent, "/v1/plans", {
        "plan_id": plan_id, "goal": f"Create bank user {args.name}", "subject": {"employee_id": "emp-admin"},
        "steps": [{"id": "s1", "action": "user.create", "params": params}],
    }))
    show("Employee approves the exact plan hash (signed by the employee's key)", signed_post(
        gw, employee, f"/v1/plans/{plan_id}/approval", {"decision": "approve", "plan_hash": plan["plan_hash"]}, prefix="x-employee"))
    issued = show("Agent asks for a token for step s1 just before executing it", signed_post(
        gw, agent, "/v1/authorize", {"action": "user.create", "params": params, "plan_id": plan_id, "step_id": "s1"}))
    token = issued["action_token"]

    def call(body: dict[str, Any], proof_key: AgentClient = agent) -> httpx.Response:
        return bank.post("/users", json=body, headers={"Authorization": f"GatewayAction {token}", "WWG-Proof": proof_key.proof("POST", f"{args.bank}/users", token)})

    show("Agent calls the bank with token + proof of possession", call(params))

    if args.attacks:
        show("ATTACK: replay the same token", call(params))
        thief = AgentClient("agent-demo", AgentClient.generate_key())
        show("ATTACK: stolen token used without the agent's key", call(params, thief))
        show("ATTACK: change parameters (balance) after authorization", call({**params, "initial_balance": "9999.00"}))
        show("ATTACK: action outside the approved plan", signed_post(gw, agent, "/v1/authorize", {
            "action": "records.delete", "params": {"record_count": 500}, "plan_id": plan_id, "step_id": "s9"}))


if __name__ == "__main__":
    main()
