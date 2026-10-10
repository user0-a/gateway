"""Mutation check: disable each protection in turn and confirm at least one test fails.

Usage: python tools/mutation_check.py   (restores every file afterwards)
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SDK = "sdk/python/wwg_sdk.py"
APP = "gateway/app.py"
STORE = "gateway/store.py"

MUTATIONS = [
    # (name, file, original, replacement)
    ("verifier: signature check", SDK, "        key.verify(signature, signing_input)\n", "        return\n"),
    ("verifier: alg must be EdDSA", SDK, 'if header.get("alg") != "EdDSA":\n            raise VerificationError("bad_alg"', 'if False:\n            raise VerificationError("bad_alg"'),
    ("verifier: token type", SDK, 'if header.get("typ") != typ:', "if False:"),
    ("verifier: issuer", SDK, 'if payload.get("iss") != self.issuer:\n            raise VerificationError("wrong_issuer"', 'if False:\n            raise VerificationError("wrong_issuer"'),
    ("verifier: audience", SDK, 'if payload.get("aud") != self.audience:', "if False:"),
    ("verifier: expiry", SDK, "if not isinstance(exp, int) or now >= exp + self.skew:", "if False:"),
    ("verifier: not-before", SDK, "if not isinstance(nbf, int) or now + self.skew < nbf:", "if False:"),
    ("verifier: action binding", SDK, 'if claims.get("action") != action:', "if False:"),
    ("verifier: params binding", SDK, 'if claims.get("params_hash") != params_hash(params):', "if False:"),
    ("verifier: token single use", SDK, 'if not self.replay.add(f"tok:{claims[\'jti\']}", claims["exp"] + self.skew):', "if False:"),
    ("verifier: plan step executes once", SDK, "if not self.replay.add(key, int(self.clock()) + 30 * 86400):", "if False:"),
    ("verifier: revoked jti", SDK, 'if claims["jti"] in set(snap.get("revoked_jti", [])):', "if False:"),
    ("verifier: suspended agent", SDK, 'if claims.get("sub") in set(snap.get("revoked_agents", [])):', "if False:"),
    ("verifier: cancelled plan", SDK, 'if claims.get("plan_id") and claims["plan_id"] in set(snap.get("revoked_plans", [])):', "if False:"),
    ("verifier: live risk tolerance", SDK, "if risk not in RISK_ORDER or RISK_ORDER[risk] > RISK_ORDER.get(tol, 1):", "if False:"),
    ("verifier: PoP required", SDK, "            if self.require_pop:\n", "            if False:\n"),
    ("verifier: proof present", SDK, "if not proof:\n            raise", "if False:\n            raise"),
    ("verifier: proof key thumbprint", SDK, "if jwk_thumbprint(jwk) != jkt:", "if False:"),
    ("verifier: proof method", SDK, 'if payload.get("htm") != method.upper():', "if False:"),
    ("verifier: proof url", SDK, 'if urlsplit(str(payload.get("htu", ""))).path != urlsplit(url).path:', "if False:"),
    ("verifier: proof bound to token", SDK, 'if payload.get("ath") != b64url(hashlib.sha256(token.encode("ascii")).digest()):', "if False:"),
    ("verifier: proof freshness", SDK, "if not isinstance(iat, int) or abs(now - iat) > self.proof_max_age:", "if False:"),
    ("verifier: proof single use", SDK, 'if not isinstance(jti, str) or not self.replay.add(f"proof:{jkt}:{jti}", int(now) + self.proof_max_age + self.skew):', "if False:"),
    ("verifier: policy snapshot signature", SDK, '_verify_sig(self._key(header.get("kid")), signing_input, sig)\n                if payload.get("iss")', 'pass\n                if payload.get("iss")'),
    ("verifier: fail closed on stale policy", SDK, "                if snap is not None and now - snap[\"iat\"] <= self.snapshot_max_age:\n                    return snap\n                raise", "                if snap is not None:\n                    return snap\n                raise"),
    ("verifier: fetched snapshot freshness", SDK, "or now - iat > self.snapshot_max_age or iat - now > self.skew or now >= exp + self.skew:", "and False:"),
    ("verifier: data table scope", SDK, 'if table not in (claims.get("tables") or []):', "if False:"),
    ("verifier: row filters", SDK, "if all(str(row.get(col)) == str(val) for col, val in filters.items()):", "if True:"),
    ("gateway: request signature", APP, "            public_key_from_x(public_key_x).verify(unb64url(signature), payload)\n", "            pass\n"),
    ("gateway: request nonce replay", APP, 'if not current_store().use_nonce(f"{prefix}:{principal_id}:{nonce}", REQUEST_MAX_SKEW * 2):', "if False:"),
    ("gateway: request timestamp window", APP, "if abs(time.time() - ts) > REQUEST_MAX_SKEW:", "if False:"),
    ("gateway: keyed agent cannot use API key", APP, '        if agent.get("public_key"):\n            await verify_signed_request', '        if False:\n            await verify_signed_request'),
    ("gateway: legacy API key comparison", APP, 'if not stored_hash or not secrets.compare_digest(hashlib.sha256(presented.encode()).hexdigest(), stored_hash):', "if False:"),
    ("gateway: only plan owner approves", APP, 'if plan["owner"] != employee["id"]:', "if False:"),
    ("gateway: exact plan hash approval", APP, 'if not secrets.compare_digest(body.plan_hash, plan["plan_hash"]):', "if False:"),
    ("gateway: role claim mismatch", APP, 'if claimed_role is not None and claimed_role != employee.get("role") and not plan:', "if False:"),
    ("gateway: role from directory", APP, 'if employee.get("role") not in roles:', "if False:"),
    ("gateway: subject must be verified", APP, "            if employee is None:\n                return deny(\"subject_not_verified\"", "            if False:\n                return deny(\"subject_not_verified\""),
    ("gateway: employee-approved plan required", APP, "if needs_plan and not plan and not plan_creation:", "if False:"),
    ("gateway: plan must be approved", APP, 'if plan.get("status") != "approved":\n            return "plan_not_approved"', 'if False:\n            return "plan_not_approved"'),
    ("gateway: plan cancellation", APP, 'if plan.get("status") == "cancelled":\n            return "plan_cancelled"', 'if False:\n            return "plan_cancelled"'),
    ("gateway: outside plan", APP, "            if plan_step is None:\n                return deny(\"outside_authorized_plan\"", "            if plan_step is None:\n                plan_step = plan[\"steps\"][0]\n            if False:\n                return deny(\"outside_authorized_plan\""),
    ("gateway: plan step parameters", APP, 'if plan_step["action"] != body.action or sha256_hex(plan_step.get("params", {})) != sha256_hex(body.params) or plan_step.get("data_policy") != body.data_policy:', "if False:"),
    ("gateway: plan belongs to agent", APP, 'if plan.get("agent_id") != agent["id"]:\n                return deny', 'if False:\n                return deny'),
    ("gateway: step issuance limit", APP, "if issued >= MAX_STEP_ISSUANCES:", "if False:"),
    ("gateway: block rules", APP, "        if block:\n            return deny(block", "        if False:\n            return deny(block"),
    ("gateway: risk tolerance", APP, "        if not risk_allowed(risk_level, tolerance):\n            return deny", "        if False:\n            return deny"),
    ("gateway: extension owner check", APP, 'if plan is None or plan.get("owner") != employee["id"]:', "if False:"),
    ("gateway: admin authentication", APP, 'if not secrets.compare_digest(request.headers.get("x-admin-key", ""), ADMIN_KEY):', "if False:"),
    ("gateway: production config check", APP, "    if problems:\n        raise RuntimeError", "    if False:\n        raise RuntimeError"),
    ("gateway: rate limit", APP, "if len(window) >= AGENT_RATE_LIMIT:", "if False:"),
    ("gateway: audit chain verification", STORE, 'if record.get("seq") != index + 1 or record.get("prev_hash") != prev or _audit_hash(record) != record.get("hash"):', "if False:"),
    ("gateway: API keys stored hashed", APP, '            agent["api_key_hash"] = hashlib.sha256(api_key.encode()).hexdigest()\n', '            agent["api_key_hash"] = hashlib.sha256(api_key.encode()).hexdigest()\n            agent["api_key"] = api_key\n'),
]


def main() -> int:
    results = []
    for name, rel, original, replacement in MUTATIONS:
        path = ROOT / rel
        source = path.read_text(encoding="utf-8")
        if source.count(original) != 1:
            results.append((name, "MUTATION NOT APPLIED (pattern count != 1)", ""))
            continue
        path.write_text(source.replace(original, replacement), encoding="utf-8")
        try:
            proc = subprocess.run([sys.executable, "-m", "pytest", "-q", "-x", "-p", "no:cacheprovider", "tests"], cwd=ROOT, capture_output=True, text=True, timeout=300)
            failed = [line.split("::")[-1].split(" ")[0] for line in proc.stdout.splitlines() if line.startswith("FAILED")]
            results.append((name, "caught" if proc.returncode != 0 else "SURVIVED", ", ".join(failed)))
        finally:
            path.write_text(source, encoding="utf-8")
    width = max(len(r[0]) for r in results)
    for name, status, tests in results:
        print(f"{name:<{width}}  {status:<8} {tests}")
    survived = [r for r in results if r[1] != "caught"]
    print(f"\n{len(results) - len(survived)}/{len(results)} protections caught by tests")
    return 1 if survived else 0


if __name__ == "__main__":
    raise SystemExit(main())
