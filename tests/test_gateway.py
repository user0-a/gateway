from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from gateway.app import create_app
from gateway.store import Store


AUTH_HEADERS = {
    "x-agent-id": "agent-1",
    "x-agent-key": "secret-agent-key-123",
    "x-employee-id": "employee-1",
    "x-employee-key": "secret-employee-key-123",
}


def seed_employee_and_mandate(store: Store, actions: list[str], data_policies: list[str] | None = None, roles: list[str] | None = None) -> None:
    store.put("employees", "employee-1", {
        "id": "employee-1",
        "name": "Employee 1",
        "api_key": "secret-employee-key-123",
        "active": True,
        "roles": roles or ["operator", "admin"],
    })
    store.put("mandates", "mandate-1", {
        "id": "mandate-1",
        "employee_id": "employee-1",
        "agent_id": "agent-1",
        "active": True,
        "allowed_actions": actions,
        "allowed_data_policies": data_policies or [],
        "max_amount": None,
        "allowed_destinations": [],
        "valid_until": None,
    })


def auth_body(request_id: str, action: str, params: dict, **extra: object) -> dict:
    return {"request_id": request_id, "action": action, "params": params, "purpose_code": "test", "mandate_id": "mandate-1", **extra}


def test_authorize_validate_and_revoke(tmp_path: Path) -> None:
    store = Store(tmp_path / "state.json")
    store.put("actions", "transfer.create", {
        "id": "transfer.create",
        "description": "",
        "service": "mini-bank",
        "operation": "transfer.create",
        "ttl_seconds": 60,
        "required_fields": ["amount"],
        "max_amount": 1000,
        "allowed_roles": ["operator"],
        "base_risk": "medium",
        "risk_rules": [],
    })
    store.put("data_policies", "accounts", {
        "id": "accounts",
        "description": "",
        "tables": ["accounts"],
        "columns": {"accounts": ["id"]},
        "row_filters": {},
        "ttl_seconds": 300,
    })
    store.put("agents", "agent-1", {
        "id": "agent-1",
        "name": "Agent 1",
        "api_key": "secret-agent-key-123",
        "active": True,
        "allowed_actions": ["transfer.create"],
        "allowed_data_policies": ["accounts"],
    })
    seed_employee_and_mandate(store, ["transfer.create"], ["accounts"], ["operator"])

    client = TestClient(create_app(store))
    response = client.post(
        "/v1/authorize",
        headers=AUTH_HEADERS,
        json=auth_body("req-1", "transfer.create", {"amount": 10}, data_policy="accounts"),
    )
    assert response.status_code == 200
    tokens = response.json()
    assert tokens["decision"] == "allow"
    assert tokens["action_token"]
    assert tokens["data_access_token"]

    validation = client.post("/v1/validate/action", json={"token": tokens["action_token"]})
    assert validation.status_code == 200
    assert validation.json()["claims"]["action"] == "transfer.create"

    revoked = client.post("/admin/tokens/revoke", headers={"x-admin-key": "dev-admin-key"}, json={"token": tokens["action_token"], "reason": "test"})
    assert revoked.status_code == 200

    inactive = client.post("/v1/introspect", json={"token": tokens["action_token"], "token_type": "action"})
    assert inactive.json() == {"active": False, "reason": "revoked"}


def test_batch_authorize_blocks_high_risk_in_low_mode(tmp_path: Path) -> None:
    store = Store(tmp_path / "state.json")
    store.state["settings"]["risk_tolerance"] = "low"
    store.put("actions", "users.select", {
        "id": "users.select",
        "description": "",
        "service": "mini-bank",
        "operation": "select.users",
        "ttl_seconds": 60,
        "required_fields": ["limit"],
        "max_amount": None,
        "allowed_roles": ["operator"],
        "base_risk": "low",
        "risk_rules": [{"field": "limit", "gte": 100, "risk": "medium"}],
    })
    store.put("actions", "records.delete", {
        "id": "records.delete",
        "description": "",
        "service": "mini-bank",
        "operation": "delete.records",
        "ttl_seconds": 60,
        "required_fields": ["record_count"],
        "max_amount": None,
        "allowed_roles": ["operator"],
        "base_risk": "medium",
        "risk_rules": [{"field": "record_count", "gte": 100, "risk": "high"}],
    })
    store.put("agents", "agent-1", {
        "id": "agent-1",
        "name": "Agent 1",
        "api_key": "secret-agent-key-123",
        "active": True,
        "allowed_actions": ["users.select", "records.delete"],
        "allowed_data_policies": [],
    })
    seed_employee_and_mandate(store, ["users.select", "records.delete"], roles=["operator"])

    client = TestClient(create_app(store))
    response = client.post(
        "/v1/authorize/batch",
        headers=AUTH_HEADERS,
        json={"actions": [
            auth_body("req-2", "users.select", {"limit": 10}),
            auth_body("req-3", "records.delete", {"record_count": 300}),
        ]},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["allowed"] == 1
    assert body["denied"] == 1
    assert body["results"][0]["decision"] == "allow"
    assert body["results"][0]["risk_level"] == "low"
    assert body["results"][1]["decision"] == "deny"
    assert body["results"][1]["risk_level"] == "high"
    assert body["results"][1]["risk_tolerance"] == "low"


def test_admin_block_rule_denies_matching_action(tmp_path: Path) -> None:
    store = Store(tmp_path / "state.json")
    store.put("actions", "users.select", {
        "id": "users.select",
        "description": "",
        "service": "mini-bank",
        "operation": "select.users",
        "ttl_seconds": 60,
        "required_fields": ["limit"],
        "max_amount": None,
        "allowed_roles": ["operator"],
        "base_risk": "low",
        "risk_rules": [],
    })
    store.put("agents", "agent-1", {
        "id": "agent-1",
        "name": "Agent 1",
        "api_key": "secret-agent-key-123",
        "active": True,
        "allowed_actions": ["users.select"],
        "allowed_data_policies": [],
    })
    seed_employee_and_mandate(store, ["users.select"], roles=["operator"])
    client = TestClient(create_app(store))

    block = client.post("/admin/blocks", headers={"x-admin-key": "dev-admin-key"}, json={"id": "block-user-select", "action": "users.select", "reason": "maintenance"})
    assert block.status_code == 200

    response = client.post(
        "/v1/authorize",
        headers=AUTH_HEADERS,
        json=auth_body("req-4", "users.select", {"limit": 10}),
    )
    assert response.status_code == 403
    assert response.json()["detail"]["reason"] == "maintenance"


def test_lowering_risk_tolerance_invalidates_existing_token(tmp_path: Path) -> None:
    store = Store(tmp_path / "state.json")
    store.state["settings"]["risk_tolerance"] = "high"
    store.put("actions", "records.delete", {
        "id": "records.delete",
        "description": "",
        "service": "mini-bank",
        "operation": "delete.records",
        "ttl_seconds": 60,
        "required_fields": ["record_count"],
        "max_amount": None,
        "allowed_roles": ["admin"],
        "base_risk": "medium",
        "risk_rules": [{"field": "record_count", "gte": 100, "risk": "high"}],
    })
    store.put("agents", "agent-1", {
        "id": "agent-1",
        "name": "Agent 1",
        "api_key": "secret-agent-key-123",
        "active": True,
        "allowed_actions": ["records.delete"],
        "allowed_data_policies": [],
    })
    seed_employee_and_mandate(store, ["records.delete"], roles=["admin"])
    client = TestClient(create_app(store))
    issued = client.post(
        "/v1/authorize",
        headers=AUTH_HEADERS,
        json=auth_body("req-5", "records.delete", {"record_count": 300}),
    )
    assert issued.status_code == 200
    token = issued.json()["action_token"]

    update = client.put("/admin/settings", headers={"x-admin-key": "dev-admin-key"}, json={"risk_tolerance": "low"})
    assert update.status_code == 200

    validation = client.post("/v1/validate/action", json={"token": token})
    assert validation.status_code == 401
    assert validation.json()["detail"] == "token revoked by current risk tolerance"


def test_system_risk_tolerance_can_be_stricter_than_global(tmp_path: Path) -> None:
    store = Store(tmp_path / "state.json")
    store.state["settings"]["risk_tolerance"] = "high"
    store.put("actions", "records.delete", {
        "id": "records.delete",
        "description": "",
        "service": "mini-bank",
        "operation": "delete.records",
        "ttl_seconds": 60,
        "required_fields": ["record_count"],
        "max_amount": None,
        "allowed_roles": ["admin"],
        "base_risk": "medium",
        "risk_rules": [{"field": "record_count", "gte": 100, "risk": "high"}],
    })
    store.put("agents", "agent-1", {
        "id": "agent-1",
        "name": "Agent 1",
        "api_key": "secret-agent-key-123",
        "active": True,
        "allowed_actions": ["records.delete"],
        "allowed_data_policies": [],
    })
    seed_employee_and_mandate(store, ["records.delete"], roles=["admin"])
    client = TestClient(create_app(store))

    update = client.put("/admin/systems/risk", headers={"x-admin-key": "dev-admin-key"}, json={"service": "mini-bank", "risk_tolerance": "low"})
    assert update.status_code == 200

    response = client.post(
        "/v1/authorize",
        headers=AUTH_HEADERS,
        json=auth_body("req-6", "records.delete", {"record_count": 300}),
    )
    assert response.status_code == 403
    detail = response.json()["detail"]
    assert detail["risk_level"] == "high"
    assert detail["risk_tolerance"] == "low"


def test_approval_and_single_use_parameter_bound_token(tmp_path: Path) -> None:
    store = Store(tmp_path / "state.json")
    store.put("actions", "transfer.create", {
        "id": "transfer.create",
        "description": "",
        "service": "mini-bank",
        "operation": "transfer.create",
        "ttl_seconds": 60,
        "required_fields": ["amount", "to_account"],
        "max_amount": 1000,
        "allowed_roles": ["operator"],
        "base_risk": "medium",
        "risk_rules": [{"field": "amount", "gte": 500, "risk": "high"}],
        "approval_required": False,
        "approval_risk_levels": ["high"],
        "allowed_purpose_codes": ["test"],
        "destination_field": "to_account",
    })
    store.put("agents", "agent-1", {
        "id": "agent-1", "name": "Agent 1", "api_key": "secret-agent-key-123", "active": True,
        "allowed_actions": ["transfer.create"], "allowed_data_policies": [],
    })
    seed_employee_and_mandate(store, ["transfer.create"], roles=["operator"])
    client = TestClient(create_app(store))
    request_body = auth_body("req-approval", "transfer.create", {"amount": 600, "to_account": "ACC-2"})

    pending = client.post("/v1/authorize", headers=AUTH_HEADERS, json=request_body)
    assert pending.status_code == 200
    assert pending.json()["decision"] == "require_approval"
    approval_id = pending.json()["approval_id"]

    approved = client.post(
        f"/admin/approvals/{approval_id}/approve",
        headers={"x-admin-key": "dev-admin-key"},
        json={"approver_id": "risk-officer-1", "reason": "verified"},
    )
    assert approved.status_code == 200

    issued = client.post("/v1/authorize", headers=AUTH_HEADERS, json={**request_body, "approval_id": approval_id})
    assert issued.status_code == 200
    token = issued.json()["action_token"]
    assert client.post("/v1/authorize", headers=AUTH_HEADERS, json={**request_body, "approval_id": approval_id}).status_code == 403

    mismatched = client.post("/v1/consume/action", json={
        "token": token, "action": "transfer.create", "service": "mini-bank", "operation": "transfer.create",
        "params": {"amount": 601, "to_account": "ACC-2"},
    })
    assert mismatched.status_code == 403

    consume_body = {
        "token": token, "action": "transfer.create", "service": "mini-bank", "operation": "transfer.create",
        "params": {"amount": 600, "to_account": "ACC-2"},
    }
    consumed = client.post("/v1/consume/action", json=consume_body)
    assert consumed.status_code == 200
    assert consumed.json()["consumed"] is True
    assert client.post("/v1/consume/action", json=consume_body).status_code == 409


def test_admin_ui_is_served(tmp_path: Path) -> None:
    client = TestClient(create_app(Store(tmp_path / "state.json")))
    response = client.get("/admin/ui")
    assert response.status_code == 200
    assert "Gateway Admin" in response.text
    assert "/admin/systems/risk" in response.text
    assert "Human Approvals" in response.text
