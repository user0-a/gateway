# WWGateWaySolution — how to run and test

| Service | Repository | Address |
|---|---|---|
| Gateway | https://github.com/user0-a/gateway | http://127.0.0.1:8001 |
| Mini-bank | https://github.com/user0-a/mini-bank | http://127.0.0.1:8000 |

Requirements: Python 3.11+, git. Optional: Java 17+ and Maven for the Java libraries.

## 1. Clone

```bash
mkdir wwgateway && cd wwgateway
git clone https://github.com/user0-a/gateway.git
git clone https://github.com/user0-a/mini-bank.git
```

## 2. Gateway (terminal 1)

```bash
cd gateway
python3 -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt
make bootstrap      # or: python scripts/bootstrap.py
make dev            # or: uvicorn gateway.app:app --host 127.0.0.1 --port 8001
```

`bootstrap` registers the demo agent `agent-demo` and two employees, `emp-operator` (operator) and
`emp-admin` (admin), with Ed25519 keys stored in `gateway/.demo_keys/` (gitignored).

## 3. Mini-bank in gateway mode (terminal 2)

```bash
cd mini-bank
pip install -r requirements.txt
BANK_GATEWAY_URL=http://127.0.0.1:8001 python3 app.py --no-browser
# Windows PowerShell: $env:BANK_GATEWAY_URL="http://127.0.0.1:8001"; python app.py --no-browser
```

In gateway mode every write needs `Authorization: GatewayAction <token>` + `WWG-Proof: <proof>`, and
every read needs `Authorization: GatewayData <token>` + `WWG-Proof`. To browse the bank's web page
during a demo, start it with `BANK_PROTECT_READS=0` (writes stay protected).

## 4. End-to-end demo with attacks (terminal 3)

```bash
cd gateway
make demo           # or: python scripts/agent_to_bank_demo.py --attacks
```

Expected output:

1. `[200]` agent proposes a plan — no tokens yet
2. `[200]` employee approves the exact plan hash (signed with the employee key)
3. `[200]` agent gets a token for step `s1` (`sender_constrained: true`)
4. `[201]` bank executes the action
5. `[401] token_replay` — same token again
6. `[401] proof_key_mismatch` — stolen token without the agent key
7. `[403] params_mismatch` — parameters changed after authorization
8. `[403] outside_authorized_plan` — action not in the approved plan

## 5. Admin

Admin panel: http://127.0.0.1:8001/admin/ui (development admin key `dev-admin-key`; production requires
`GATEWAY_ENV=production` with a strong `GATEWAY_ADMIN_KEY` and `GATEWAY_ISSUER`).

Useful calls (header `x-admin-key: dev-admin-key`): `PUT /admin/settings` (global risk),
`PUT /admin/systems/risk` (per system), `POST /admin/blocks`, `POST /admin/tokens/revoke`,
`POST /admin/agents/{id}/suspend`, `POST /admin/plans/{id}/cancel`, `POST /admin/keys/rotate`,
`GET /admin/audit/verify`, `GET /admin/audit/export`.
Changes reach the bank within the policy snapshot lifetime (10 s); tokens already issued are affected.

## 6. Tests and evidence

```bash
cd gateway && make test && make mutation && make bench && make report
cd ../mini-bank && pytest
cd ../gateway/java && mvn verify     # Java libraries (needs Maven)
```
