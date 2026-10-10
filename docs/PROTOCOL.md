# WWGateWay protocol (v0.2)

This document is the normative description of the tokens and requests exchanged between AI agents,
the gateway, employees and bank systems. The Python SDK (`sdk/python/wwg_sdk.py`) and the Java
verifier (`java/wwgateway-verifier-core`) implement it and are tested against shared vectors.

## 1. Parties and keys

| Party | Key | Used for |
|---|---|---|
| Gateway | Ed25519, `kid`, rotated (`active` + `retiring`), published at `GET /.well-known/jwks.json` | signs action tokens, data tokens, policy snapshots |
| Agent | Ed25519, public key registered by an admin | signs requests to the gateway and proofs of possession |
| Employee | Ed25519 (device / passkey in production), public key registered by an admin | signs plan approvals and extension decisions |
| Bank system | none | verifies everything locally with the gateway's public keys |

No shared secrets are used. Bank systems can verify tokens but cannot create them.

## 2. Canonical JSON

Every hash and signature is computed over canonical JSON (RFC 8785 profile): object keys sorted by
UTF-16 code units, no whitespace, ECMAScript string escaping, integers exact, other numbers in
ECMAScript `Number::toString` form, NaN/Infinity rejected. **Send money amounts as strings**
(`"4500.00"`).

`params_hash = hex(sha256(canonical(params)))`

## 3. Signed requests (agent → gateway, employee → gateway)

Headers `x-agent-*` (or `x-employee-*`): `-id`, `-timestamp` (unix seconds), `-nonce` (unique),
`-signature` = base64url(Ed25519(canonical({"m": METHOD, "p": path?query, "ts": ts, "n": nonce,
"bh": base64url(sha256(raw body))}))).

The gateway rejects: unknown or inactive principal, timestamp outside ±60 s, reused nonce,
invalid signature (which also covers any change to method, path or body).

## 4. Execution plans

1. `POST /v1/plans` (agent): `plan_id`, `goal`, `subject.employee_id`, `steps[]` (`id`, `action`,
   `params`, optional `data_policy`). Every step is pre-checked; no tokens are issued.
   Response: `requires_approval` with `plan_hash`, or `rejected` with the denied steps.
2. `POST /v1/plans/{id}/approval` (employee, signed): `{"decision": "approve", "plan_hash": ...}`.
   Only the plan owner, only the exact hash, only before expiry.
3. `POST /v1/authorize` (agent) with `plan_id` + `step_id` just before running the step. The action
   and parameters must equal the approved step; risk and block rules are re-evaluated now.
4. Anything not in the plan → `outside_authorized_plan`; the agent must call
   `POST /v1/plans/{id}/extensions`, approved by the owner (signed) or an admin.

`plan_hash = sha256(canonical({plan_id, goal, owner, agent_id, expires_at, steps: [{id, action, params_hash, data_policy}]}))`

Role-restricted actions, actions marked `requires_plan`, and anything above `medium` risk are only
issued inside an employee-approved plan. The subject (employee and role) always comes from the
signed plan and the employee directory, never from the agent.

## 5. Action token (`typ: wwg-action+jwt`)

Compact JWS, `alg: EdDSA`, `kid`. Claims:

| Claim | Meaning |
|---|---|
| `iss` | gateway issuer id |
| `aud` | target system (e.g. `mini-bank`); a token for another system is rejected |
| `sub` | agent id |
| `act_for` | employee on whose behalf the agent acts |
| `action`, `operation` | the single authorized action |
| `params_hash` | hash of the exact parameters |
| `risk_level` | assessed at issuance; re-checked against the live tolerance |
| `plan_id`, `step_id`, `plan_hash` | plan binding (when issued from a plan) |
| `cnf.jkt` | RFC 7638 thumbprint of the agent key (sender constraint) |
| `iat`, `nbf`, `exp`, `jti` | 30 s for financial actions, otherwise per policy; single use |

Data token (`typ: wwg-data+jwt`) carries `tables`, `columns`, `row_filters` (resolved from the
employee directory, e.g. `owner = subject.customer_name`) instead of `action`/`params_hash`.

## 6. Proof of possession (`typ: wwg-proof+jwt`, header `WWG-Proof`)

Signed by the agent key; header contains the agent `jwk`. Claims: `htm` (method), `htu` (URL; the
path is compared), `iat` (±60 s), `jti` (single use), `ath` = base64url(sha256(token)).

## 7. Verification in a bank system

1. JWS: `alg` must be `EdDSA`, `typ` must match, no `crit`, known `kid` (JWKS refreshed on unknown kid), valid signature.
2. `iss`, `aud`, `nbf`/`exp` (±5 s skew), `jti` present.
3. Action tokens: `action` equals the endpoint's action; `params_hash` equals the request parameters.
4. Policy snapshot (`GET /v1/policy-snapshot`, signed, valid 10 s): token not revoked, agent not
   suspended, plan not cancelled, `risk_level` ≤ min(global, per-system tolerance).
   **Fail closed:** no fresh snapshot within 30 s → `policy_unavailable`.
5. Proof of possession as in §6.
6. Consume `jti` and, for plan tokens, `plan_id:step_id` (each step executes once).

## 8. Error codes (identical in Python and Java)

`malformed_token`, `bad_alg`, `wrong_token_type`, `bad_header`, `bad_signature`, `unknown_kid`,
`keys_unavailable`, `wrong_issuer`, `wrong_audience`, `expired`, `not_yet_valid`, `wrong_action`,
`params_mismatch`, `revoked`, `agent_revoked`, `plan_revoked`, `risk_tolerance`,
`policy_unavailable`, `bad_policy`, `pop_required`, `proof_missing`, `bad_proof`, `bad_key`,
`proof_key_mismatch`, `proof_method_mismatch`, `proof_url_mismatch`, `proof_token_mismatch`,
`proof_stale`, `proof_replay`, `token_replay`, `step_already_executed`, `table_not_allowed`,
`token_required`.
