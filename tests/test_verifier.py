"""Downstream (bank-side) verification with wwg_sdk.GatewayVerifier — every check must fail closed."""
from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

from helpers import ADMIN, AgentClient, World
from wwg_sdk import VerificationError, apply_data_scope, sign_jws

URL = "http://bank/transfers"
STEP = {"id": "s2", "action": "transfer.create", "params": {"from_account": 1, "to_account": 2, "amount": "100.00"}}


def setup(tmp_path: Path):
    w = World(tmp_path)
    w.approved_plan()
    token = w.step_token("plan-1", STEP)["action_token"]
    return w, token


def verify(w: World, token: str, proof: str | None, v=None, **overrides):
    v = v or w.verifier()
    args = {"method": "POST", "url": URL, "action": "transfer.create", "params": STEP["params"], **overrides}
    return v.verify_action(token, proof, **args)


def code(fn) -> str:
    with pytest.raises(VerificationError) as exc:
        fn()
    return exc.value.code


def test_happy_path_and_single_use(tmp_path: Path) -> None:
    w, token = setup(tmp_path)
    v = w.verifier()
    assert verify(w, token, w.agent.proof("POST", URL, token), v)["sub"] == "agent-1"
    assert code(lambda: verify(w, token, w.agent.proof("POST", URL, token), v)) == "token_replay"


def test_same_plan_step_cannot_execute_twice_even_with_a_new_token(tmp_path: Path) -> None:
    w, token = setup(tmp_path)
    v = w.verifier()
    verify(w, token, w.agent.proof("POST", URL, token), v)
    second = w.step_token("plan-1", STEP)["action_token"]
    assert code(lambda: verify(w, second, w.agent.proof("POST", URL, second), v)) == "step_already_executed"


def test_binding_checks(tmp_path: Path) -> None:
    w, token = setup(tmp_path)
    p = lambda: w.agent.proof("POST", URL, token)  # noqa: E731
    assert code(lambda: verify(w, token, p(), params={**STEP["params"], "amount": "9000.00"})) == "params_mismatch"
    assert code(lambda: verify(w, token, p(), action="account.close")) == "wrong_action"
    other = w.verifier()
    other.audience = "card-system"
    assert code(lambda: verify(w, token, p(), v=other)) == "wrong_audience"


def test_proof_of_possession(tmp_path: Path) -> None:
    w, token = setup(tmp_path)
    attacker = AgentClient("agent-1", AgentClient.generate_key())
    assert code(lambda: verify(w, token, None)) == "proof_missing"
    assert code(lambda: verify(w, token, attacker.proof("POST", URL, token))) == "proof_key_mismatch"
    assert code(lambda: verify(w, token, w.agent.proof("GET", URL, token))) == "proof_method_mismatch"
    assert code(lambda: verify(w, token, w.agent.proof("POST", "http://bank/accounts/1", token))) == "proof_url_mismatch"
    assert code(lambda: verify(w, token, w.agent.proof("POST", URL, token + "x"))) == "proof_token_mismatch"
    import hashlib
    import time
    from wwg_sdk import b64url
    old_proof = sign_jws(w.agent_key, {"typ": "wwg-proof+jwt", "jwk": w.agent.jwk}, {
        "htm": "POST", "htu": URL, "iat": int(time.time()) - 120, "jti": "old-proof",
        "ath": b64url(hashlib.sha256(token.encode()).digest())})
    assert code(lambda: verify(w, token, old_proof)) == "proof_stale"


def test_proof_replay(tmp_path: Path) -> None:
    w, token = setup(tmp_path)
    v = w.verifier()
    proof = w.agent.proof("POST", URL, token)
    v.verify_action(token, proof, method="POST", url=URL, action="transfer.create", params=STEP["params"], consume=False)
    assert code(lambda: v.verify_action(token, proof, method="POST", url=URL, action="transfer.create", params=STEP["params"])) == "proof_replay"


def test_time_checks(tmp_path: Path) -> None:
    import time
    w, token = setup(tmp_path)
    late = w.verifier(clock=lambda: time.time() + 3600)
    assert code(lambda: verify(w, token, w.agent.proof("POST", URL, token), late)) == "expired"
    early = w.verifier(clock=lambda: time.time() - 3600)
    assert code(lambda: verify(w, token, w.agent.proof("POST", URL, token), early)) == "not_yet_valid"


def test_forged_and_confused_tokens(tmp_path: Path) -> None:
    w, token = setup(tmp_path)
    h, p, s = token.split(".")
    payload = json.loads(base64.urlsafe_b64decode(p + "=="))
    payload["params_hash"] = "0" * 64
    forged_payload = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    assert code(lambda: verify(w, f"{h}.{forged_payload}.{s}", None)) == "bad_signature"
    header = json.loads(base64.urlsafe_b64decode(h + "=="))
    for alg in ("none", "HS256"):
        bad = base64.urlsafe_b64encode(json.dumps({**header, "alg": alg}).encode()).rstrip(b"=").decode()
        assert code(lambda: verify(w, f"{bad}.{p}.{s}", None)) == "bad_alg"
    rogue = sign_jws(AgentClient.generate_key(), {"kid": header["kid"], "typ": "wwg-action+jwt"}, payload)
    assert code(lambda: verify(w, rogue, None)) == "bad_signature"
    unknown = sign_jws(AgentClient.generate_key(), {"kid": "rogue-kid", "typ": "wwg-action+jwt"}, payload)
    assert code(lambda: verify(w, unknown, None)) == "unknown_kid"
    assert code(lambda: verify(w, "not-a-token", None)) == "malformed_token"


def test_data_token_cannot_be_used_as_action_token(tmp_path: Path) -> None:
    w = World(tmp_path)
    w.approved_plan(steps=[{"id": "s1", "action": "customer.read", "params": {"customer_id": "c-1"}, "data_policy": "accounts"}])
    tokens = w.step_token("plan-1", {"id": "s1", "action": "customer.read", "params": {"customer_id": "c-1"}}, data_policy="accounts")
    data = tokens["data_access_token"]
    assert code(lambda: w.verifier().verify_action(data, w.agent.proof("POST", URL, data), method="POST", url=URL, action="customer.read", params={"customer_id": "c-1"})) == "wrong_token_type"
    claims = w.verifier().verify_data_access(data, w.agent.proof("GET", "http://bank/accounts", data), method="GET", url="http://bank/accounts", table="accounts")
    assert claims["row_filters"] == {"accounts": {"owner": "Ala"}}          # resolved from the employee directory
    assert code(lambda: w.verifier().verify_data_access(data, w.agent.proof("GET", "http://bank/ops", data), method="GET", url="http://bank/ops", table="operations")) == "table_not_allowed"
    rows = [{"id": 1, "owner": "Ala", "balance": "1.00", "secret": "x"}, {"id": 2, "owner": "Ola", "balance": "2.00", "secret": "y"}]
    assert apply_data_scope(rows, claims, "accounts") == [{"id": 1, "owner": "Ala", "balance": "1.00"}]


def test_unbound_legacy_tokens_are_rejected_when_pop_is_required(tmp_path: Path) -> None:
    w = World(tmp_path)
    t = w.http.post("/v1/authorize", headers={"x-agent-id": "legacy", "x-agent-key": "legacy-agent-key-123456"}, json={"action": "users.select", "params": {"limit": 1}}).json()["action_token"]
    assert code(lambda: w.verifier().verify_action(t, None, method="GET", url="/u", action="users.select", params={"limit": 1})) == "pop_required"


def test_revocation_risk_suspension_and_plan_cancellation_reach_the_bank(tmp_path: Path) -> None:
    w, token = setup(tmp_path)
    proof = lambda: w.agent.proof("POST", URL, token)  # noqa: E731
    w.http.post("/admin/tokens/revoke", headers=ADMIN, json={"token": token})
    assert code(lambda: verify(w, token, proof())) == "revoked"

    w2, token2 = setup(tmp_path / "2")
    w2.http.put("/admin/settings", headers=ADMIN, json={"risk_tolerance": "low"})   # token risk is medium
    assert code(lambda: verify(w2, token2, w2.agent.proof("POST", URL, token2))) == "risk_tolerance"

    w3, token3 = setup(tmp_path / "3")
    w3.http.post("/admin/agents/agent-1/suspend", headers=ADMIN)
    assert code(lambda: verify(w3, token3, w3.agent.proof("POST", URL, token3))) == "agent_revoked"

    w4, token4 = setup(tmp_path / "4")
    w4.http.post("/admin/plans/plan-1/cancel", headers=ADMIN)
    assert code(lambda: verify(w4, token4, w4.agent.proof("POST", URL, token4))) == "plan_revoked"


def test_fail_closed_when_policy_cannot_be_refreshed(tmp_path: Path) -> None:
    import time
    w, token = setup(tmp_path)
    v = w.verifier(snapshot_max_age=30)
    assert verify(w, token, w.agent.proof("POST", URL, token), v, )  # warms caches (consumes token)
    token2 = w.step_token("plan-1", {**STEP, "id": "s1", "action": "customer.read", "params": {"customer_id": "c-1"}})["action_token"]

    def broken(url: str):
        raise ConnectionError("gateway down")

    v._fetch = broken
    v.clock = lambda: time.time() + 31
    assert code(lambda: v.verify_action(token2, w.agent.proof("POST", "/r", token2), method="POST", url="/r", action="customer.read", params={"customer_id": "c-1"})) == "policy_unavailable"
    v.clock = time.time
    v._snapshot["iat"] -= 31  # cached snapshot too old, gateway unreachable
    assert code(lambda: v.verify_action(token2, w.agent.proof("POST", "/r", token2), method="POST", url="/r", action="customer.read", params={"customer_id": "c-1"})) == "policy_unavailable"


def test_wrong_issuer_is_rejected(tmp_path: Path) -> None:
    w, token = setup(tmp_path)
    v = w.verifier()
    v.issuer = "https://evil-gateway.example"
    assert code(lambda: verify(w, token, w.agent.proof("POST", URL, token), v)) == "wrong_issuer"


def test_replayed_old_policy_snapshot_is_rejected(tmp_path: Path) -> None:
    import time
    w, token = setup(tmp_path)
    old = w.http.get("/v1/policy-snapshot").json()          # captured before the revocation
    w.http.post("/admin/tokens/revoke", headers=ADMIN, json={"token": token})
    v = w.verifier(clock=lambda: time.time() + 40)          # attacker replays it 40 s later
    real = v._fetch
    v._fetch = lambda url: old if url.endswith("/v1/policy-snapshot") else real(url)
    assert code(lambda: v.policy()) == "policy_unavailable"


def test_policy_snapshot_is_signed(tmp_path: Path) -> None:
    w, token = setup(tmp_path)
    v = w.verifier()
    real = v._fetch

    def tampered(url: str):
        data = real(url)
        if url.endswith("/v1/policy-snapshot"):
            h, p, s = data["snapshot"].split(".")
            payload = json.loads(base64.urlsafe_b64decode(p + "=="))
            payload["risk_tolerance"] = "critical"
            data["snapshot"] = h + "." + base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode() + "." + s
        return data

    v._fetch = tampered
    assert code(lambda: verify(w, token, w.agent.proof("POST", URL, token), v)) == "bad_signature"
