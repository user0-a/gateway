from __future__ import annotations

import json

import httpx


BASE_URL = "http://127.0.0.1:8001"
AUTH_HEADERS = {
    "x-agent-id": "agent-demo",
    "x-agent-key": "demo-agent-key-please-change",
    "x-employee-id": "employee-demo",
    "x-employee-key": "demo-employee-key-please-change",
}
ADMIN_HEADERS = {"x-admin-key": "dev-admin-key"}


def show(title: str, response: httpx.Response) -> dict:
    payload = response.json()
    print(f"\n=== {title} ({response.status_code}) ===")
    safe_payload = {**payload}
    for key, value in safe_payload.items():
        if key.endswith("_token") and isinstance(value, str):
            safe_payload[key] = value[:32] + "..."
    print(json.dumps(safe_payload, indent=2))
    response.raise_for_status()
    return payload


def main() -> None:
    request_body = {
        "request_id": "hackathon-transfer-001",
        "action": "transfer.create",
        "params": {"from_account": "ACC-1", "to_account": "ACC-2", "amount": 600},
        "data_policy": "accounts-read-basic",
        "purpose_code": "customer-payment",
        "reason": "Hackathon demo transfer",
        "mandate_id": "mandate-demo",
    }

    with httpx.Client(base_url=BASE_URL, timeout=10) as client:
        pending = show("1. REQUIRE APPROVAL", client.post("/v1/authorize", headers=AUTH_HEADERS, json=request_body))
        approval_id = pending["approval_id"]

        show(
            "2. HUMAN APPROVAL",
            client.post(
                f"/admin/approvals/{approval_id}/approve",
                headers=ADMIN_HEADERS,
                json={"approver_id": "risk-officer-demo", "reason": "Approved during demo"},
            ),
        )

        allowed = show(
            "3. ALLOW AND ISSUE TOKEN",
            client.post("/v1/authorize", headers=AUTH_HEADERS, json={**request_body, "approval_id": approval_id}),
        )
        consume_body = {
            "token": allowed["action_token"],
            "action": "transfer.create",
            "service": "mini-bank",
            "operation": "transfer.create",
            "params": request_body["params"],
        }
        show("4. EXECUTE / CONSUME", client.post("/v1/consume/action", json=consume_body))

        replay = client.post("/v1/consume/action", json=consume_body)
        print(f"\n=== 5. REPLAY BLOCKED ({replay.status_code}) ===")
        print(json.dumps(replay.json(), indent=2))
        if replay.status_code != 409:
            raise RuntimeError("Expected replay to be blocked")


if __name__ == "__main__":
    main()
