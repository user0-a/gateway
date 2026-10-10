"""Functional behaviour of the gateway: policies, risk, blocks, plans, extensions, admin."""
from __future__ import annotations

from pathlib import Path

from helpers import ADMIN, World


def test_low_risk_unrestricted_action_is_allowed_directly(tmp_path: Path) -> None:
    w = World(tmp_path)
    r = w.agent_post("/v1/authorize", {"action": "users.select", "params": {"limit": 10}})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["decision"] == "allow" and body["risk_level"] == "low" and body["sender_constrained"] is True


def test_role_restricted_action_requires_employee_approved_plan(tmp_path: Path) -> None:
    w = World(tmp_path)
    r = w.agent_post("/v1/authorize", {"action": "transfer.create", "params": {"from_account": 1, "to_account": 2, "amount": "10"}, "subject": {"employee_id": "emp-anna", "role": "operator"}})
    assert r.status_code == 403
    assert r.json()["detail"]["reason"] == "employee_approved_plan_required"


def test_agent_cannot_self_assert_a_subject_or_role(tmp_path: Path) -> None:
    w = World(tmp_path)
    # no employee at all -> the role cannot be verified
    r = w.agent_post("/v1/authorize", {"action": "records.delete", "params": {"record_count": 5}, "subject": {"role": "admin"}})
    assert r.json()["detail"]["reason"] == "subject_not_verified"
    # agent claims admin for an operator employee -> mismatch
    r = w.agent_post("/v1/authorize", {"action": "records.delete", "params": {"record_count": 5}, "subject": {"employee_id": "emp-anna", "role": "admin"}})
    assert r.json()["detail"]["reason"] == "subject_role_mismatch"
    # inside a plan the role always comes from the directory: operator cannot get an admin-only step
    r = w.agent_post("/v1/plans", {"plan_id": "p-role", "goal": "cleanup", "subject": {"employee_id": "emp-anna", "role": "admin"}, "steps": [{"id": "s1", "action": "records.delete", "params": {"record_count": 5}}]})
    assert r.json()["decision"] == "rejected"
    assert r.json()["denied_steps"][0]["reason"] == "subject role not allowed"


def test_block_rule_denies_matching_action(tmp_path: Path) -> None:
    w = World(tmp_path)
    w.http.post("/admin/blocks", headers=ADMIN, json={"id": "no-select", "action": "users.select", "reason": "maintenance"})
    r = w.agent_post("/v1/authorize", {"action": "users.select", "params": {"limit": 10}})
    assert r.status_code == 403 and r.json()["detail"]["reason"] == "maintenance"


def test_batch_reports_each_decision(tmp_path: Path) -> None:
    w = World(tmp_path)
    w.http.put("/admin/settings", headers=ADMIN, json={"risk_tolerance": "low"})
    r = w.agent_post("/v1/authorize/batch", {"actions": [{"action": "users.select", "params": {"limit": 10}}, {"action": "users.select", "params": {"limit": 500}}]})
    body = r.json()
    assert body["allowed"] == 1 and body["denied"] == 1
    assert body["results"][1]["reason"] == "risk level exceeds gateway tolerance"


def test_system_risk_tolerance_is_stricter_than_global(tmp_path: Path) -> None:
    w = World(tmp_path)
    w.http.put("/admin/systems/risk", headers=ADMIN, json={"service": "mini-bank", "risk_tolerance": "low"})
    r = w.agent_post("/v1/authorize", {"action": "users.select", "params": {"limit": 500}})
    assert r.json()["detail"]["risk_tolerance"] == "low"


def test_plan_is_not_usable_before_employee_approval(tmp_path: Path) -> None:
    w = World(tmp_path)
    r = w.agent_post("/v1/plans", {"plan_id": "p1", "goal": "pay", "subject": {"employee_id": "emp-anna"}, "steps": [{"id": "s1", "action": "customer.read", "params": {"customer_id": "c-1"}}]})
    created = r.json()
    assert created["decision"] == "requires_approval" and "action_token" not in str(created)
    t = w.agent_post("/v1/authorize", {"action": "customer.read", "params": {"customer_id": "c-1"}, "plan_id": "p1", "step_id": "s1"})
    assert t.json()["detail"]["reason"] == "plan_not_approved"


def test_plan_requires_known_employee_owner(tmp_path: Path) -> None:
    w = World(tmp_path)
    r = w.agent_post("/v1/plans", {"plan_id": "p1", "goal": "pay", "subject": {"role": "admin"}, "steps": [{"id": "s1", "action": "users.select", "params": {"limit": 1}}]})
    assert r.status_code == 400 and r.json()["detail"] == "plan_requires_active_employee_owner"


def test_only_the_owner_can_approve_and_only_the_exact_hash(tmp_path: Path) -> None:
    w = World(tmp_path)
    created = w.agent_post("/v1/plans", {"plan_id": "p1", "goal": "pay", "subject": {"employee_id": "emp-anna"}, "steps": [{"id": "s1", "action": "customer.read", "params": {"customer_id": "c-1"}}]}).json()
    wrong_employee = w.employee_post("/v1/plans/p1/approval", {"decision": "approve", "plan_hash": created["plan_hash"]}, w.marek)
    assert wrong_employee.status_code == 403
    wrong_hash = w.employee_post("/v1/plans/p1/approval", {"decision": "approve", "plan_hash": "0" * 64}, w.anna)
    assert wrong_hash.status_code == 409 and wrong_hash.json()["detail"] == "plan_hash_mismatch"
    unsigned = w.http.post("/v1/plans/p1/approval", headers={"x-employee-id": "emp-anna"}, json={"decision": "approve", "plan_hash": created["plan_hash"]})
    assert unsigned.status_code == 401
    ok = w.employee_post("/v1/plans/p1/approval", {"decision": "approve", "plan_hash": created["plan_hash"]}, w.anna)
    assert ok.status_code == 200 and ok.json()["plan"]["status"] == "approved"


def test_step_token_is_bound_to_plan_and_outside_actions_need_extension(tmp_path: Path) -> None:
    w = World(tmp_path)
    created = w.approved_plan()
    step = {"id": "s2", "action": "transfer.create", "params": {"from_account": 1, "to_account": 2, "amount": "100.00"}}
    token = w.step_token("plan-1", step)
    assert token["decision"] == "allow" and token["expires_in"] == 30   # financial -> 30 s
    claims = w.verifier().verify_action(token["action_token"], w.agent.proof("POST", "http://bank/transfers", token["action_token"]), method="POST", url="http://bank/transfers", action="transfer.create", params=step["params"])
    assert claims["plan_hash"] == created["plan_hash"] and claims["step_id"] == "s2" and claims["act_for"] == "emp-anna"

    outside = w.agent_post("/v1/authorize", {"action": "users.select", "params": {"limit": 10}, "plan_id": "plan-1", "step_id": "s9"})
    assert outside.json()["detail"]["reason"] == "outside_authorized_plan"
    assert outside.json()["detail"]["required"] == "request_plan_extension"

    changed = w.agent_post("/v1/authorize", {"action": "transfer.create", "params": {**step["params"], "amount": "900.00"}, "plan_id": "plan-1", "step_id": "s2"})
    assert changed.json()["detail"]["reason"] == "plan_step_mismatch"

    foreign = w.agent_post("/v1/authorize", {"action": step["action"], "params": step["params"], "plan_id": "plan-1", "step_id": "s2"}, client=w.other_agent)
    assert foreign.json()["detail"]["reason"] == "plan_belongs_to_another_agent"


def test_plan_extension_needs_owner_signature(tmp_path: Path) -> None:
    w = World(tmp_path)
    w.approved_plan()
    ext = w.agent_post("/v1/plans/plan-1/extensions", {"step": {"id": "s3", "action": "users.select", "params": {"limit": 5}}, "reason": "need customer list"})
    assert ext.status_code == 200, ext.text
    ext_id = ext.json()["extension_id"]
    spoofed = w.http.post(f"/v1/plans/extensions/{ext_id}/employee-decision", headers={"x-employee-id": "emp-anna"}, json={"decision": "approve"})
    assert spoofed.status_code == 401
    not_owner = w.employee_post(f"/v1/plans/extensions/{ext_id}/employee-decision", {"decision": "approve"}, w.marek)
    assert not_owner.status_code == 403
    ok = w.employee_post(f"/v1/plans/extensions/{ext_id}/employee-decision", {"decision": "approve"}, w.anna)
    assert ok.status_code == 200
    token = w.agent_post("/v1/authorize", {"action": "users.select", "params": {"limit": 5}, "plan_id": "plan-1", "step_id": "s3"})
    assert token.status_code == 200


def test_cancelled_plan_issues_no_more_tokens(tmp_path: Path) -> None:
    w = World(tmp_path)
    w.approved_plan()
    w.http.post("/admin/plans/plan-1/cancel", headers=ADMIN)
    r = w.agent_post("/v1/authorize", {"action": "customer.read", "params": {"customer_id": "c-1"}, "plan_id": "plan-1", "step_id": "s1"})
    assert r.json()["detail"]["reason"] == "plan_cancelled"


def test_step_issuance_is_limited(tmp_path: Path) -> None:
    w = World(tmp_path)
    w.approved_plan()
    step = {"id": "s1", "action": "customer.read", "params": {"customer_id": "c-1"}}
    for _ in range(3):
        w.step_token("plan-1", step)
    r = w.agent_post("/v1/authorize", {"action": step["action"], "params": step["params"], "plan_id": "plan-1", "step_id": "s1"})
    assert r.json()["detail"]["reason"] == "step_issuance_limit"


def test_admin_ui_has_no_prefilled_secret(tmp_path: Path) -> None:
    w = World(tmp_path)
    page = w.http.get("/admin/ui")
    assert page.status_code == 200 and 'value="dev-admin-key"' not in page.text
