from __future__ import annotations

import argparse
from typing import Any

import httpx


def authorize(gateway_url: str, agent_id: str, agent_key: str, action: str, params: dict[str, Any], role: str) -> str:
    response = httpx.post(
        f"{gateway_url}/v1/authorize",
        headers={"x-agent-id": agent_id, "x-agent-key": agent_key},
        json={"action": action, "params": params, "subject": {"role": role}},
        timeout=10,
    )
    response.raise_for_status()
    return response.json()["action_token"]


def create_user(bank_url: str, gateway_url: str, agent_id: str, agent_key: str, name: str, email: str, initial_balance: str) -> dict[str, Any]:
    params = {"email": email, "name": name, "initial_balance": initial_balance}
    token = authorize(gateway_url, agent_id, agent_key, "user.create", params, "admin")
    response = httpx.post(
        f"{bank_url}/users",
        headers={"Authorization": f"GatewayAction {token}"},
        json=params,
        timeout=10,
    )
    response.raise_for_status()
    return response.json()


def main() -> None:
    parser = argparse.ArgumentParser(description="Demo agent: gateway authorization -> mini-bank request")
    parser.add_argument("--gateway", default="http://127.0.0.1:8001")
    parser.add_argument("--bank", default="http://127.0.0.1:8000")
    parser.add_argument("--agent-id", default="agent-demo")
    parser.add_argument("--agent-key", default="demo-agent-key-please-change")
    parser.add_argument("--name", default="Jane Agent")
    parser.add_argument("--email", default="jane.agent@example.com")
    parser.add_argument("--initial-balance", default="25.00")
    args = parser.parse_args()

    result = create_user(args.bank, args.gateway, args.agent_id, args.agent_key, args.name, args.email, args.initial_balance)
    print(result)


if __name__ == "__main__":
    main()
