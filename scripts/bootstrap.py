from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from gateway.store import Store


state_path = Path(os.environ.get("GATEWAY_STATE", ROOT / "data" / "state.json"))
store = Store(state_path)

store.put("actions", "transfer.create", {
    "id": "transfer.create",
    "description": "Create a bank transfer",
    "service": "mini-bank",
    "operation": "transfer.create",
    "ttl_seconds": 60,
    "required_fields": ["from_account", "to_account", "amount"],
    "max_amount": 1000,
    "allowed_roles": ["operator", "admin"],
    "base_risk": "medium",
    "risk_rules": [{"field": "amount", "gte": 500, "risk": "high"}],
    "approval_required": False,
    "approval_risk_levels": ["high", "critical"],
    "allowed_purpose_codes": ["customer-payment", "operations-demo"],
    "destination_field": "to_account",
})

store.put("actions", "user.create", {
    "id": "user.create",
    "description": "Create a bank user",
    "service": "mini-bank",
    "operation": "user.create",
    "ttl_seconds": 60,
    "required_fields": ["email", "name"],
    "max_amount": None,
    "allowed_roles": ["admin"],
    "base_risk": "medium",
    "risk_rules": [],
    "approval_required": True,
    "approval_risk_levels": [],
    "allowed_purpose_codes": ["customer-onboarding"],
    "destination_field": None,
})

store.put("actions", "users.select", {
    "id": "users.select",
    "description": "Read users from mini-bank",
    "service": "mini-bank",
    "operation": "select.users",
    "ttl_seconds": 120,
    "required_fields": ["limit"],
    "max_amount": None,
    "allowed_roles": ["operator", "admin"],
    "base_risk": "low",
    "risk_rules": [{"field": "limit", "gte": 100, "risk": "medium"}],
    "approval_required": False,
    "approval_risk_levels": [],
    "allowed_purpose_codes": ["customer-support", "operations-demo"],
    "destination_field": None,
})

store.put("actions", "records.delete", {
    "id": "records.delete",
    "description": "Delete records in mini-bank",
    "service": "mini-bank",
    "operation": "delete.records",
    "ttl_seconds": 30,
    "required_fields": ["record_count"],
    "max_amount": None,
    "allowed_roles": ["admin"],
    "base_risk": "medium",
    "risk_rules": [{"field": "record_count", "gte": 100, "risk": "high"}, {"field": "record_count", "gte": 1000, "risk": "critical"}],
    "approval_required": False,
    "approval_risk_levels": ["high", "critical"],
    "allowed_purpose_codes": ["data-retention"],
    "destination_field": None,
})

store.put("data_policies", "accounts-read-basic", {
    "id": "accounts-read-basic",
    "description": "Read basic account data only",
    "tables": ["accounts"],
    "columns": {"accounts": ["id", "owner_id", "balance", "currency"]},
    "row_filters": {"accounts": {"tenant_id": "subject.tenant_id"}},
    "ttl_seconds": 300,
})

store.put("agents", "agent-demo", {
    "id": "agent-demo",
    "name": "Demo Agent",
    "api_key": "demo-agent-key-please-change",
    "active": True,
    "allowed_actions": ["transfer.create", "user.create", "users.select", "records.delete"],
    "allowed_data_policies": ["accounts-read-basic"],
})

store.put("employees", "employee-demo", {
    "id": "employee-demo",
    "name": "Demo Bank Operator",
    "api_key": "demo-employee-key-please-change",
    "active": True,
    "roles": ["operator", "admin"],
})

store.put("mandates", "mandate-demo", {
    "id": "mandate-demo",
    "employee_id": "employee-demo",
    "agent_id": "agent-demo",
    "active": True,
    "allowed_actions": ["transfer.create", "user.create", "users.select", "records.delete"],
    "allowed_data_policies": ["accounts-read-basic"],
    "max_amount": 750,
    "allowed_destinations": ["ACC-2", "ACC-TRUSTED"],
    "valid_until": None,
})

store.state["settings"]["risk_tolerance"] = "high"
store.state["settings"].setdefault("system_risk_tolerances", {})
store.state["settings"]["system_risk_tolerances"].setdefault("mini-bank", "high")
store.save()

store.audit({"decision": "admin_change", "op": "bootstrap"})
print(f"Bootstrapped gateway state at {state_path}")
print("Agent: agent-demo")
print("Agent key: demo-agent-key-please-change")
print("Employee: employee-demo")
print("Employee key: demo-employee-key-please-change")
print("Mandate: mandate-demo")
