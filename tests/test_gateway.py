from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from gateway.app import create_app
from gateway.store import Store


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

    client = TestClient(create_app(store))
    response = client.post(
        "/v1/authorize",
        headers={"x-agent-id": "agent-1", "x-agent-key": "secret-agent-key-123"},
        json={"action": "transfer.create", "params": {"amount": 10}, "data_policy": "accounts", "subject": {"role": "operator"}},
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

    client = TestClient(create_app(store))
    response = client.post(
        "/v1/authorize/batch",
        headers={"x-agent-id": "agent-1", "x-agent-key": "secret-agent-key-123"},
        json={"actions": [
            {"action": "users.select", "params": {"limit": 10}, "subject": {"role": "operator"}},
            {"action": "records.delete", "params": {"record_count": 300}, "subject": {"role": "operator"}},
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
    client = TestClient(create_app(store))

    block = client.post("/admin/blocks", headers={"x-admin-key": "dev-admin-key"}, json={"id": "block-user-select", "action": "users.select", "reason": "maintenance"})
    assert block.status_code == 200

    response = client.post(
        "/v1/authorize",
        headers={"x-agent-id": "agent-1", "x-agent-key": "secret-agent-key-123"},
        json={"action": "users.select", "params": {"limit": 10}, "subject": {"role": "operator"}},
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
    client = TestClient(create_app(store))
    issued = client.post(
        "/v1/authorize",
        headers={"x-agent-id": "agent-1", "x-agent-key": "secret-agent-key-123"},
        json={"action": "records.delete", "params": {"record_count": 300}, "subject": {"role": "admin"}},
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
    client = TestClient(create_app(store))

    update = client.put("/admin/systems/risk", headers={"x-admin-key": "dev-admin-key"}, json={"service": "mini-bank", "risk_tolerance": "low"})
    assert update.status_code == 200

    response = client.post(
        "/v1/authorize",
        headers={"x-agent-id": "agent-1", "x-agent-key": "secret-agent-key-123"},
        json={"action": "records.delete", "params": {"record_count": 300}, "subject": {"role": "admin"}},
    )
    assert response.status_code == 403
    detail = response.json()["detail"]
    assert detail["risk_level"] == "high"
    assert detail["risk_tolerance"] == "low"


def test_admin_ui_is_served(tmp_path: Path) -> None:
    client = TestClient(create_app(Store(tmp_path / "state.json")))
    response = client.get("/admin/ui")
    assert response.status_code == 200
    assert "Gateway Admin" in response.text
    assert "/admin/systems/risk" in response.text
