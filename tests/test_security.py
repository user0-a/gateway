"""Attacks on the gateway itself: authentication, replay, keys, audit, configuration."""
from __future__ import annotations

import importlib
import json
import time
from pathlib import Path

import pytest

from helpers import ADMIN, AgentClient, World, canonicalize


def test_signed_agent_requests_reject_missing_wrong_replayed_stale_and_tampered(tmp_path: Path) -> None:
    w = World(tmp_path)
    payload = {"action": "users.select", "params": {"limit": 10}}
    body = canonicalize(payload)

    assert w.http.post("/v1/authorize", headers={"x-agent-id": "agent-1"}, json=payload).status_code == 401  # unsigned

    impostor = AgentClient("agent-1", AgentClient.generate_key())  # knows the id, not the key
    assert w.agent_post("/v1/authorize", payload, client=impostor).status_code == 401

    headers = {"content-type": "application/json", **w.agent.signed_headers("POST", "/v1/authorize", body)}
    assert w.http.post("/v1/authorize", content=body, headers=headers).status_code == 200
    assert w.http.post("/v1/authorize", content=body, headers=headers).status_code == 401  # replay

    tampered = canonicalize({"action": "users.select", "params": {"limit": 99}})
    headers = {"content-type": "application/json", **w.agent.signed_headers("POST", "/v1/authorize", body)}
    assert w.http.post("/v1/authorize", content=tampered, headers=headers).status_code == 401  # body changed

    from gateway.crypto import b64url, request_signing_payload
    ts = int(time.time()) - 600   # correctly signed, but too old
    signed = request_signing_payload("POST", "/v1/authorize", ts, "old-nonce", body)
    old = {"content-type": "application/json", "x-agent-id": "agent-1", "x-agent-timestamp": str(ts), "x-agent-nonce": "old-nonce", "x-agent-signature": b64url(w.agent_key.sign(signed))}
    stale = w.http.post("/v1/authorize", content=body, headers=old)
    assert stale.status_code == 401 and stale.json()["detail"] == "request timestamp outside allowed window"


def test_agent_with_registered_key_cannot_fall_back_to_api_key(tmp_path: Path) -> None:
    w = World(tmp_path)
    r = w.http.post("/v1/authorize", headers={"x-agent-id": "agent-1", "x-agent-key": "anything-anything"}, json={"action": "users.select", "params": {"limit": 1}})
    assert r.status_code == 401


def test_legacy_agent_works_only_for_unrestricted_actions_and_gets_unbound_tokens(tmp_path: Path) -> None:
    w = World(tmp_path)
    h = {"x-agent-id": "legacy", "x-agent-key": "legacy-agent-key-123456"}
    ok = w.http.post("/v1/authorize", headers=h, json={"action": "users.select", "params": {"limit": 1}})
    assert ok.status_code == 200 and ok.json()["sender_constrained"] is False
    assert w.http.post("/v1/authorize", headers={**h, "x-agent-key": "wrong-key-wrong-key"}, json={"action": "users.select", "params": {"limit": 1}}).status_code == 401
    # API keys are stored only as hashes
    assert "legacy-agent-key-123456" not in json.dumps(w.store.state)


def test_tokens_are_eddsa_jws_and_jwks_is_published(tmp_path: Path) -> None:
    w = World(tmp_path)
    token = w.agent_post("/v1/authorize", {"action": "users.select", "params": {"limit": 1}}).json()["action_token"]
    import base64
    header = json.loads(base64.urlsafe_b64decode(token.split(".")[0] + "=="))
    assert header["alg"] == "EdDSA" and header["typ"] == "wwg-action+jwt"
    jwks = w.http.get("/.well-known/jwks.json").json()
    assert header["kid"] in [k["kid"] for k in jwks["keys"]]
    assert all("d" not in k for k in jwks["keys"])  # no private material


def test_key_rotation_keeps_old_tokens_valid_until_retired(tmp_path: Path) -> None:
    w = World(tmp_path)
    v = w.verifier()
    t = w.agent_post("/v1/authorize", {"action": "users.select", "params": {"limit": 1}}).json()["action_token"]
    old_kid = w.app.state.keyring.active_kid()
    w.http.post("/admin/keys/rotate", headers=ADMIN)
    assert w.app.state.keyring.active_kid() != old_kid
    assert v.verify_action(t, w.agent.proof("POST", "/x", t), method="POST", url="/x", action="users.select", params={"limit": 1})
    assert w.http.post(f"/admin/keys/{old_kid}/retire", headers=ADMIN).status_code == 200
    t2 = w.agent_post("/v1/authorize", {"action": "users.select", "params": {"limit": 1}}).json()["action_token"]
    fresh = w.verifier()
    with pytest.raises(Exception) as exc:
        fresh.verify_action(t, w.agent.proof("POST", "/x", t), method="POST", url="/x", action="users.select", params={"limit": 1})
    assert exc.value.code == "unknown_kid"
    assert fresh.verify_action(t2, w.agent.proof("POST", "/x", t2), method="POST", url="/x", action="users.select", params={"limit": 1})


def test_audit_chain_detects_modification_and_deletion(tmp_path: Path) -> None:
    w = World(tmp_path)
    w.agent_post("/v1/authorize", {"action": "users.select", "params": {"limit": 1}})
    assert w.http.get("/admin/audit/verify", headers=ADMIN).json()["intact"] is True
    events = w.store.state["audit"]
    events[2]["decision"] = "allow-edited"
    assert w.http.get("/admin/audit/verify", headers=ADMIN).json() == {"intact": False, "broken_at_seq": 3, "entries": len(events)}
    w2 = World(tmp_path / "b")
    w2.agent_post("/v1/authorize", {"action": "users.select", "params": {"limit": 1}})
    del w2.store.state["audit"][1]
    assert w2.http.get("/admin/audit/verify", headers=ADMIN).json()["intact"] is False


def test_audit_export_is_json_lines(tmp_path: Path) -> None:
    w = World(tmp_path)
    lines = w.http.get("/admin/audit/export?since=2", headers=ADMIN).text.strip().splitlines()
    records = [json.loads(line) for line in lines]
    assert records and all(r["seq"] > 2 for r in records)


def test_admin_endpoints_and_introspection_require_admin_key(tmp_path: Path) -> None:
    w = World(tmp_path)
    for method, path in (("get", "/admin/settings"), ("get", "/admin/audit"), ("post", "/admin/keys/rotate"), ("get", "/admin/employees")):
        assert getattr(w.http, method)(path).status_code == 401
    assert w.http.post("/v1/introspect", json={"token": "x.y.z"}).status_code == 401


def test_agent_rate_limit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import gateway.app as gw
    monkeypatch.setattr(gw, "AGENT_RATE_LIMIT", 3)
    w = World(tmp_path)
    codes = [w.agent_post("/v1/authorize", {"action": "users.select", "params": {"limit": 1}}).status_code for _ in range(4)]
    assert codes == [200, 200, 200, 429]


def test_production_refuses_dev_configuration(monkeypatch: pytest.MonkeyPatch) -> None:
    import gateway.app as gw
    monkeypatch.setattr(gw, "ENV", "production")
    monkeypatch.setattr(gw, "ADMIN_KEY", "dev-admin-key")
    monkeypatch.setattr(gw, "ALLOW_LEGACY_AGENT_KEYS", True)
    with pytest.raises(RuntimeError, match="Refusing to start in production"):
        gw.check_production_config()
    monkeypatch.setattr(gw, "ADMIN_KEY", "x" * 40)
    monkeypatch.setattr(gw, "ALLOW_LEGACY_AGENT_KEYS", False)
    monkeypatch.setattr(gw, "ISSUER", "https://gateway.bank.example")
    gw.check_production_config()


def test_canonicalization_is_identical_in_gateway_and_sdk() -> None:
    from gateway.jcs import canonicalize as gw_canon
    samples = [
        {"amount": "12.50", "to": 2, "z": None, "a": [1, 2.5, True, {"ż": "ą\n\t\"", "A": 1e-7}]},
        {"big": 12345678901234567890, "f": 1.0, "e": 1e21, "small": 0.00001, "neg": -0.5},
        {"\u20ac": 1, "\U0001f600": 2, "a": 3, "B": 4},
    ]
    for s in samples:
        assert gw_canon(s) == canonicalize(s)
