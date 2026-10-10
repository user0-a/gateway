"""Generate cross-language test vectors so the Java verifier is checked against the Python reference.

Usage: python tools/make_java_vectors.py  -> java/wwgateway-verifier-core/src/test/resources/vectors.json
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk" / "python"))
from wwg_sdk import AgentClient, b64url, canonicalize, jwk_thumbprint, params_hash, public_jwk, sign_jws  # noqa: E402

T = 1_790_000_000
ISS, AUD = "wwgateway-vectors", "core-payments"
gw_key, agent_key, thief_key = (AgentClient.generate_key() for _ in range(3))
agent_jwk, thief_jwk = public_jwk(agent_key.public_key()), public_jwk(thief_key.public_key())
KID = "vec-kid-1"


def token(typ: str, **claims):
    base = {"iss": ISS, "aud": AUD, "sub": "agent-1", "iat": T, "nbf": T, "exp": T + 30, "jti": claims.pop("jti", "tok-1"),
            "risk_level": "medium", "cnf": {"jkt": jwk_thumbprint(agent_jwk)}}
    return sign_jws(gw_key, {"kid": claims.pop("kid", KID), "typ": typ}, {**base, **claims})


def proof(tok: str, method="POST", url="https://bank.example/transfers", key=agent_key, jwk=agent_jwk, iat=T, jti="p-1"):
    return sign_jws(key, {"typ": "wwg-proof+jwt", "jwk": jwk}, {"htm": method, "htu": url, "iat": iat, "jti": jti,
                                                                "ath": b64url(hashlib.sha256(tok.encode()).digest())})


PARAMS = {"from_account": "PL61109010140000071219812874", "to_account": "DE89370400440532013000", "amount": "4500.00", "title": "Faktura INV-847 żółć"}
PH = params_hash(PARAMS)
good = token("wwg-action+jwt", action="transfer.create", params_hash=PH, plan_id="plan-1", step_id="s2", plan_hash="ab" * 32)


def call(tok, prf, expect, method="POST", url="https://bank.example/transfers", action="transfer.create", params=PARAMS):
    return {"kind": "action", "token": tok, "proof": prf, "method": method, "url": url, "action": action, "params": params, "expect": expect}


h, p, s = good.split(".")
tampered_payload = json.loads(__import__("base64").urlsafe_b64decode(p + "=="))
tampered_payload["params_hash"] = "0" * 64
tampered = h + "." + b64url(canonicalize(tampered_payload)) + "." + s
hs256_header = b64url(canonicalize({"alg": "HS256", "kid": KID, "typ": "wwg-action+jwt"}))
second_token_same_step = token("wwg-action+jwt", jti="tok-2", action="transfer.create", params_hash=PH, plan_id="plan-1", step_id="s2")

cases = [
    {"name": "valid action token", "calls": [call(good, proof(good), "ok")]},
    {"name": "token replay", "calls": [call(good, proof(good, jti="a"), "ok"), call(good, proof(good, jti="b"), "token_replay")]},
    {"name": "plan step executes once", "calls": [call(good, proof(good, jti="a"), "ok"), call(second_token_same_step, proof(second_token_same_step, jti="b"), "step_already_executed")]},
    {"name": "params changed", "calls": [call(good, proof(good), "params_mismatch", params={**PARAMS, "amount": "45000.00"})]},
    {"name": "wrong action", "calls": [call(good, proof(good), "wrong_action", action="account.close")]},
    {"name": "wrong audience", "calls": [call(token("wwg-action+jwt", aud="card-system", action="transfer.create", params_hash=PH), None, "wrong_audience")]},
    {"name": "wrong issuer", "calls": [call(token("wwg-action+jwt", iss="evil", action="transfer.create", params_hash=PH), None, "wrong_issuer")]},
    {"name": "expired", "calls": [call(token("wwg-action+jwt", exp=T - 60, action="transfer.create", params_hash=PH), None, "expired")]},
    {"name": "not yet valid", "calls": [call(token("wwg-action+jwt", nbf=T + 600, action="transfer.create", params_hash=PH), None, "not_yet_valid")]},
    {"name": "tampered payload", "calls": [call(tampered, None, "bad_signature")]},
    {"name": "alg confusion", "calls": [call(hs256_header + "." + p + "." + s, None, "bad_alg")]},
    {"name": "unknown kid", "calls": [call(token("wwg-action+jwt", kid="nope", action="transfer.create", params_hash=PH), None, "unknown_kid")]},
    {"name": "data token as action token", "calls": [call(token("wwg-data+jwt", tables=["accounts"]), None, "wrong_token_type")]},
    {"name": "proof missing", "calls": [call(good, None, "proof_missing")]},
    {"name": "proof by thief", "calls": [call(good, proof(good, key=thief_key, jwk=thief_jwk), "proof_key_mismatch")]},
    {"name": "proof wrong method", "calls": [call(good, proof(good, method="GET"), "proof_method_mismatch")]},
    {"name": "proof wrong url", "calls": [call(good, proof(good, url="https://bank.example/accounts/1"), "proof_url_mismatch")]},
    {"name": "proof for another token", "calls": [call(good, proof(second_token_same_step), "proof_token_mismatch")]},
    {"name": "stale proof", "calls": [call(good, proof(good, iat=T - 300), "proof_stale")]},
    {"name": "proof replay", "calls": [call(good, proof(good, jti="same"), "ok"), call(second_token_same_step, proof(second_token_same_step, jti="same"), "proof_replay")]},
    {"name": "revoked", "calls": [call(token("wwg-action+jwt", jti="revoked-1", action="transfer.create", params_hash=PH), None, "revoked")]},
    {"name": "suspended agent", "calls": [call(token("wwg-action+jwt", sub="agent-bad", action="transfer.create", params_hash=PH), None, "agent_revoked")]},
    {"name": "risk above tolerance", "calls": [call(token("wwg-action+jwt", risk_level="critical", action="transfer.create", params_hash=PH), None, "risk_tolerance")]},
    {"name": "unbound token", "calls": [call(sign_jws(gw_key, {"kid": KID, "typ": "wwg-action+jwt"}, {"iss": ISS, "aud": AUD, "sub": "agent-1", "iat": T, "nbf": T, "exp": T + 30, "jti": "u", "risk_level": "low", "action": "transfer.create", "params_hash": PH}), None, "pop_required")]},
    {"name": "malformed", "calls": [call("not.a-token", None, "malformed_token")]},
]
data_tok = token("wwg-data+jwt", jti="d1", tables=["accounts"], columns={"accounts": ["id", "owner"]}, row_filters={"accounts": {"owner": "Ala"}})
cases += [
    {"name": "data access ok", "calls": [{"kind": "data", "token": data_tok, "proof": proof(data_tok, method="GET", url="https://bank.example/accounts"), "method": "GET", "url": "https://bank.example/accounts", "table": "accounts", "expect": "ok",
                                          "rows": [{"id": 1, "owner": "Ala", "balance": "1.00"}, {"id": 2, "owner": "Ola", "balance": "2.00"}], "scoped": [{"id": 1, "owner": "Ala"}]}]},
    {"name": "data table not allowed", "calls": [{"kind": "data", "token": data_tok, "proof": proof(data_tok, method="GET", url="https://bank.example/ops"), "method": "GET", "url": "https://bank.example/ops", "table": "operations", "expect": "table_not_allowed"}]},
]

snapshot = sign_jws(gw_key, {"kid": KID, "typ": "wwg-policy+jwt"}, {"iss": ISS, "iat": T, "exp": T + 10, "risk_tolerance": "high", "system_risk_tolerances": {AUD: "high"},
                                                                    "revoked_jti": ["revoked-1"], "revoked_agents": ["agent-bad"], "revoked_plans": []})
canonical_inputs = [
    '{"b":2,"a":1}', '{"amount":"12.50","to":2,"z":null,"t":true,"f":false}', '[1.0, 1e-7, 0.00001, 1e21, 123.456, -0.5, 1e16, 5e-324, 1.7976931348623157e308]',
    '{"\\u20ac":1,"\\ud83d\\ude00":2,"a":3,"B":4}', '{"s":"z\\u00f3\\u0142\\u0107 \\" \\\\ \\n \\t \\u0001 \\u007f /"}', '{"big":12345678901234567890123,"neg":-0,"exp":2E3}',
    '[0.1, 0.2, 0.30000000000000004, 2.2250738585072014e-308, 9007199254740993.0, 1e-6, 1e-7, 123e-20, 4.35, 0.000001234, 1e300, 3.14159265358979, 100.5]',
    '[1e22, 1.5e21, 9.999999999999999e20, 0.5e-6, 2.5e-7, 1.1e-5]',
]
vectors = {
    "now": T + 2, "issuer": ISS, "audience": AUD,
    "jwks": {"keys": [{**public_jwk(gw_key.public_key()), "kid": KID, "alg": "EdDSA"}]},
    "snapshot": snapshot,
    "canonical": [{"json": text, "canonical": canonicalize(json.loads(text)).decode("utf-8"), "sha256": params_hash(json.loads(text))} for text in canonical_inputs],
    "cases": cases,
}
out = ROOT / "java" / "wwgateway-verifier-core" / "src" / "test" / "resources" / "vectors.json"
out.parent.mkdir(parents=True, exist_ok=True)
out.write_text(json.dumps(vectors, indent=1, ensure_ascii=False), encoding="utf-8")
print(f"wrote {out} ({len(cases)} cases, {len(canonical_inputs)} canonicalization vectors)")
