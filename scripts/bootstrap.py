from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from gateway.store import Store

sys.path.insert(0, str(ROOT / "sdk" / "python"))
from wwg_sdk import AgentClient  # noqa: E402

KEY_DIR = Path(os.environ.get("WWG_DEMO_KEYS", ROOT / ".demo_keys"))


def demo_key(name: str) -> AgentClient:
    """Development keys for the demo agent and employees (gitignored). Real deployments
    generate keys inside the agent runtime / employee device and register only public keys."""
    KEY_DIR.mkdir(parents=True, exist_ok=True)
    path = KEY_DIR / f"{name}.pem"
    if path.exists():
        key = AgentClient.load_key(path.read_bytes())
    else:
        key = AgentClient.generate_key()
        path.write_bytes(AgentClient.dump_key(key))
        os.chmod(path, 0o600)
    return AgentClient(name, key)


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

store.put("actions", "customer.read", {
    "id": "customer.read",
    "description": "Read customer profile data",
    "service": "mini-bank",
    "operation": "customer.read",
    "ttl_seconds": 120,
    "required_fields": ["customer_id"],
    "max_amount": None,
    "allowed_roles": ["operator", "admin"],
    "base_risk": "medium",
    "risk_rules": [],
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
    "columns": {"accounts": ["id", "owner", "balance"]},
    "row_filters": {},
    "ttl_seconds": 300,
})

store.put("data_policies", "accounts-own-customer", {
    "id": "accounts-own-customer",
    "description": "Only the accounts of the customer the employee is serving",
    "tables": ["accounts", "operations"],
    "columns": {"accounts": ["id", "owner", "balance"]},
    "row_filters": {"accounts": {"owner": "subject.customer_name"}},
    "ttl_seconds": 300,
})

agent = demo_key("agent-demo")
store.put("agents", "agent-demo", {
    "id": "agent-demo",
    "name": "Demo Agent",
    "public_key": agent.jwk["x"],
    "active": True,
    "allowed_actions": ["transfer.create", "user.create", "account.create", "deposit.create", "account.close", "users.select", "customer.read", "records.delete"],
    "allowed_data_policies": ["accounts-read-basic", "accounts-own-customer"],
})

for employee_id, name, role in (("emp-operator", "Anna Operator", "operator"), ("emp-admin", "Marek Admin", "admin")):
    employee = demo_key(employee_id)
    store.put("employees", employee_id, {
        "id": employee_id, "name": name, "role": role, "public_key": employee.jwk["x"],
        "attributes": {"customer_name": "Jane Agent"}, "active": True,
    })

store.state["settings"]["risk_tolerance"] = "high"
store.state["settings"].setdefault("system_risk_tolerances", {})
store.state["settings"]["system_risk_tolerances"].setdefault("mini-bank", "high")
store.save()

store.audit({"decision": "admin_change", "op": "bootstrap"})
print(f"Bootstrapped gateway state at {state_path}")
print("Agent: agent-demo (Ed25519 key in .demo_keys/agent-demo.pem)")
print("Employees: emp-operator (operator), emp-admin (admin) — keys in .demo_keys/")
