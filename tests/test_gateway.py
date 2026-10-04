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


def test_plan_integrity_requires_extension_for_new_action(tmp_path: Path) -> None:
    store = Store(tmp_path / "state.json")
    for action_id, fields in {
        "invoice.read": ["invoice_id"],
        "customer.read": ["customer_id"],
    }.items():
        store.put("actions", action_id, {
            "id": action_id,
            "description": "",
            "service": "mini-bank",
            "operation": action_id,
            "ttl_seconds": 60,
            "required_fields": fields,
            "max_amount": None,
            "allowed_roles": ["admin"],
            "base_risk": "medium",
            "risk_rules": [],
        })
    store.put("agents", "agent-1", {
        "id": "agent-1",
        "name": "Agent 1",
        "api_key": "secret-agent-key-123",
        "active": True,
        "allowed_actions": ["invoice.read", "customer.read"],
        "allowed_data_policies": [],
    })
    client = TestClient(create_app(store))
    headers = {"x-agent-id": "agent-1", "x-agent-key": "secret-agent-key-123"}

    plan = client.post("/v1/plans/authorize", headers=headers, json={
        "plan_id": "plan-847",
        "goal": "Pay invoice INV-847",
        "subject": {"role": "admin"},
        "steps": [{"id": "s1", "action": "invoice.read", "params": {"invoice_id": "INV-847"}}],
    })
    assert plan.status_code == 200
    plan_hash = plan.json()["plan_hash"]

    outside = client.post("/v1/authorize", headers=headers, json={
        "action": "customer.read",
        "params": {"customer_id": "CUST-1"},
        "subject": {"role": "admin"},
        "plan_id": "plan-847",
        "step_id": "s2",
    })
    assert outside.status_code == 403
    assert outside.json()["detail"]["reason"] == "outside_authorized_plan"
    assert outside.json()["detail"]["required"] == "request_plan_extension"

    extension = client.post("/v1/plans/plan-847/extensions", headers=headers, json={
        "reason": "Need customer data to validate invoice owner",
        "step": {"id": "s2", "action": "customer.read", "params": {"customer_id": "CUST-1"}},
    })
    assert extension.status_code == 200
    extension_id = extension.json()["extension_id"]

    decision = client.post(f"/admin/plans/extensions/{extension_id}/decision", headers={"x-admin-key": "dev-admin-key"}, json={"decision": "approve"})
    assert decision.status_code == 200
    assert decision.json()["plan"]["plan_hash"] != plan_hash

    retry = client.post("/v1/authorize", headers=headers, json={
        "action": "customer.read",
        "params": {"customer_id": "CUST-1"},
        "subject": {"role": "admin"},
        "plan_id": "plan-847",
        "step_id": "s2",
    })
    assert retry.status_code == 200
    assert retry.json()["decision"] == "allow"

    token_check = client.post("/v1/validate/action", json={"token": retry.json()["action_token"]})
    claims = token_check.json()["claims"]
    assert claims["plan_id"] == "plan-847"
    assert claims["step_id"] == "s2"
    assert claims["plan_hash"] == decision.json()["plan"]["plan_hash"]


def test_employee_owner_can_approve_plan_extension(tmp_path: Path) -> None:
    store = Store(tmp_path / "state.json")
    for action_id, fields in {"users.select": ["limit"], "customer.read": ["customer_id"]}.items():
        store.put("actions", action_id, {
            "id": action_id,
            "description": "",
            "service": "mini-bank",
            "operation": action_id,
            "ttl_seconds": 60,
            "required_fields": fields,
            "max_amount": None,
            "allowed_roles": ["admin"],
            "base_risk": "medium",
            "risk_rules": [],
        })
    store.put("agents", "agent-1", {
        "id": "agent-1",
        "name": "Agent 1",
        "api_key": "secret-agent-key-123",
        "active": True,
        "allowed_actions": ["users.select", "customer.read"],
        "allowed_data_policies": [],
    })
    client = TestClient(create_app(store))
    agent_headers = {"x-agent-id": "agent-1", "x-agent-key": "secret-agent-key-123"}

    plan = client.post("/v1/plans/authorize", headers=agent_headers, json={
        "plan_id": "plan-employee-1",
        "goal": "Handle employee-owned task",
        "subject": {"role": "admin", "employee_id": "emp-123"},
        "steps": [{"id": "s1", "action": "users.select", "params": {"limit": 10}}],
    })
    assert plan.status_code == 200

    extension = client.post("/v1/plans/plan-employee-1/extensions", headers=agent_headers, json={
        "reason": "Employee asked to include customer data",
        "step": {"id": "s2", "action": "customer.read", "params": {"customer_id": "CUST-99"}},
    })
    extension_id = extension.json()["extension_id"]

    wrong_employee = client.post(f"/v1/plans/extensions/{extension_id}/employee-decision", headers={"x-employee-id": "emp-999"}, json={"decision": "approve"})
    assert wrong_employee.status_code == 403

    approval = client.post(f"/v1/plans/extensions/{extension_id}/employee-decision", headers={"x-employee-id": "emp-123"}, json={"decision": "approve", "comment": "I requested this task"})
    assert approval.status_code == 200
    assert approval.json()["extension"]["decided_by_type"] == "employee"
    assert approval.json()["extension"]["decided_by"] == "emp-123"

    retry = client.post("/v1/authorize", headers=agent_headers, json={
        "action": "customer.read",
        "params": {"customer_id": "CUST-99"},
        "subject": {"role": "admin", "employee_id": "emp-123"},
        "plan_id": "plan-employee-1",
        "step_id": "s2",
    })
    assert retry.status_code == 200
    assert retry.json()["decision"] == "allow"
