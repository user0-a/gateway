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
})

store.put("actions", "user.create", {
    "id": "user.create",
    "description": "Create a bank user and a default account",
    "service": "mini-bank",
    "operation": "user.create",
    "ttl_seconds": 60,
    "required_fields": ["email", "name"],
    "max_amount": None,
    "allowed_roles": ["admin"],
    "base_risk": "medium",
    "risk_rules": [],
})

store.put("actions", "account.create", {
    "id": "account.create",
    "description": "Create a bank account",
    "service": "mini-bank",
    "operation": "account.create",
    "ttl_seconds": 60,
    "required_fields": ["owner", "initial_balance"],
    "max_amount": None,
    "allowed_roles": ["operator", "admin"],
    "base_risk": "medium",
    "risk_rules": [],
})

store.put("actions", "deposit.create", {
    "id": "deposit.create",
    "description": "Deposit funds into an account",
    "service": "mini-bank",
    "operation": "deposit.create",
    "ttl_seconds": 60,
    "required_fields": ["account_id", "amount"],
    "max_amount": 1000,
    "allowed_roles": ["operator", "admin"],
    "base_risk": "medium",
    "risk_rules": [{"field": "amount", "gte": 500, "risk": "high"}],
})

store.put("actions", "account.close", {
    "id": "account.close",
    "description": "Close an account",
    "service": "mini-bank",
    "operation": "account.close",
    "ttl_seconds": 60,
    "required_fields": ["account_id", "transfer_to"],
    "max_amount": None,
    "allowed_roles": ["admin"],
    "base_risk": "high",
    "risk_rules": [],
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
    "allowed_actions": ["transfer.create", "user.create", "account.create", "deposit.create", "account.close", "users.select", "records.delete"],
    "allowed_data_policies": ["accounts-read-basic"],
})

store.state["settings"]["risk_tolerance"] = "high"
store.state["settings"].setdefault("system_risk_tolerances", {})
store.state["settings"]["system_risk_tolerances"].setdefault("mini-bank", "high")
store.save()

store.audit({"decision": "admin_change", "op": "bootstrap"})
print(f"Bootstrapped gateway state at {state_path}")
print("Agent: agent-demo")
print("Agent key: demo-agent-key-please-change")
