# Gateway

Serwis autoryzacyjny dla agentow AI. Agent wysyla zamiar wykonania akcji, gateway go uwierzytelnia, autoryzuje i wystawia krotkotrwale tokeny:

- `action_token` - dla konkretnej akcji, np. `user.create`, `transfer.create`.
- `data_access_token` - dla dostepu do konkretnych tabel, kolumn i filtrow wierszy.

Docelowy serwis, np. `mini-bank`, nie musi ufac agentowi. Waliduje tylko token w gatewayu albo lokalnie po uzgodnieniu sekretu.

## Flow Systemu

1. Pracownik banku prosi agenta o wykonanie pracy.
2. Agent uklada liste akcji, np. `users.select`, `records.delete`, `transfer.create`.
3. Agent wysyla liste do `POST /v1/authorize/batch`.
4. Gateway uwierzytelnia agenta, sprawdza polityki, blokady admina i globalny poziom tolerancji ryzyka.
5. Gateway zwraca tokeny tylko dla akcji zaakceptowanych.
6. Agent wywoluje docelowe serwisy, np. `mini-bank`, z tokenami.
7. Serwis docelowy waliduje token przez gateway przed wykonaniem akcji.

## Plan Integrity

Gateway moze zatwierdzic caly plan wykonania, policzyc `plan_hash` i powiazac kazdy `action_token` z konkretnym krokiem planu:

- `plan_id`
- `plan_hash`
- `step_id`
- `params_hash`

Jesli agent sprobuje wykonac akcje, ktorej nie ma w zatwierdzonym planie, gateway odrzuci request z `outside_authorized_plan` i wymusi `request_plan_extension`.

Glowne endpointy:

- `POST /v1/plans/authorize` - zatwierdza plan i wydaje tokeny dla krokow.
- `POST /v1/plans/{plan_id}/extensions` - agent prosi o dodanie kroku do planu.
- `POST /admin/plans/extensions/{extension_id}/decision` - admin zatwierdza albo odrzuca extension.
- `POST /v1/plans/extensions/{extension_id}/employee-decision` - pracownik-wlasciciel zadania zatwierdza albo odrzuca extension.
- `GET /v1/plans/{plan_id}` - podglad planu dla admina.

Employee approval dziala, gdy plan ma w `subject` pole `employee_id`, `user_id` albo `id`. Request decyzyjny musi miec naglowek `x-employee-id` zgodny z wlascicielem planu.

## Risk Tolerance

Gateway ma globalny poziom tolerancji ryzyka:

- `low`
- `medium`
- `high`
- `critical`

Akcja ma `base_risk` oraz opcjonalne `risk_rules`, ktore podbijaja ryzyko na podstawie parametrow. Przyklad:

- `users.select` z `limit=10` -> `low`
- `records.delete` z `record_count=300` -> `high`

Jesli gateway dziala w trybie `low`, akcja `high` nie dostanie tokena. Jesli admin obnizy tolerancje po wydaniu tokena, walidacja juz wydanego tokena tez przestanie przechodzic.

Admin moze tez ustawic tolerancje per system, np. `mini-bank=low`. Obowiazuje bardziej restrykcyjny limit z pary: globalny risk tolerance i risk tolerance dla danego systemu.

## GUI Administratora

Panel jest dostepny pod:

```text
http://127.0.0.1:8001/admin/ui
```

W GUI administrator moze:

- ustawic global risk level,
- ustawic risk level dla konkretnego systemu, np. `mini-bank`,
- dodawac i usuwac blokady akcji/zapytan,
- podejrzec akcje, systemy i aktywne blokady.

Panel pyta o `admin key` i wysyla go jako `x-admin-key` do admin API.

## Uruchomienie

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
make dev
```

Domyslne zmienne dev:

- `GATEWAY_ADMIN_KEY=dev-admin-key`
- `GATEWAY_TOKEN_SECRET=dev-change-me`
- `GATEWAY_STATE=data/state.json`

W realnym srodowisku ustaw je samodzielnie.

## Szybki Start

Zaladuj przykladowe polityki i agenta:

```bash
make bootstrap
```

Popros gateway o token akcji i token dostepu do danych:

```bash
curl -s http://127.0.0.1:8001/v1/authorize \
  -H 'content-type: application/json' \
  -H 'x-agent-id: agent-demo' \
  -H 'x-agent-key: demo-agent-key-please-change' \
  -d '{
    "action": "transfer.create",
    "params": {"from_account": "ACC-1", "to_account": "ACC-2", "amount": 100},
    "data_policy": "accounts-read-basic",
    "subject": {"user_id": "u1", "role": "operator"},
    "reason": "demo transfer"
  }'
```

Popros gateway o tokeny dla listy akcji:

```bash
curl -s http://127.0.0.1:8001/v1/authorize/batch \
  -H 'content-type: application/json' \
  -H 'x-agent-id: agent-demo' \
  -H 'x-agent-key: demo-agent-key-please-change' \
  -d '{
    "actions": [
      {"action": "users.select", "params": {"limit": 10}, "subject": {"role": "operator"}},
      {"action": "records.delete", "params": {"record_count": 300}, "subject": {"role": "admin"}}
    ]
  }'
```

Ustaw globalna tolerancje ryzyka:

```bash
curl -s -X PUT http://127.0.0.1:8001/admin/settings \
  -H 'content-type: application/json' \
  -H 'x-admin-key: dev-admin-key' \
  -d '{"risk_tolerance":"low"}'
```

Ustaw tolerancje ryzyka dla systemu, np. `mini-bank`:

```bash
curl -s -X PUT http://127.0.0.1:8001/admin/systems/risk \
  -H 'content-type: application/json' \
  -H 'x-admin-key: dev-admin-key' \
  -d '{"service":"mini-bank","risk_tolerance":"low"}'
```

Usun override dla systemu:

```bash
curl -s -X PUT http://127.0.0.1:8001/admin/systems/risk \
  -H 'content-type: application/json' \
  -H 'x-admin-key: dev-admin-key' \
  -d '{"service":"mini-bank","risk_tolerance":null}'
```

Zablokuj konkretna akcje lub zapytanie:

```bash
curl -s http://127.0.0.1:8001/admin/blocks \
  -H 'content-type: application/json' \
  -H 'x-admin-key: dev-admin-key' \
  -d '{"id":"block-large-delete","action":"records.delete","min_records":100,"reason":"large delete disabled"}'
```

Walidacja tokena przez serwis wykonawczy:

```bash
curl -s http://127.0.0.1:8001/v1/introspect \
  -H 'content-type: application/json' \
  -d '{"token":"PASTE_TOKEN_HERE","token_type":"action"}'
```

## Glowne Endpointy

- `POST /v1/authorize` - agent prosi o autoryzacje akcji.
- `POST /v1/authorize/batch` - agent prosi o tokeny dla listy akcji.
- `POST /v1/introspect` - sprawdzenie dowolnego tokena.
- `POST /v1/validate/action` - walidacja tokena akcji.
- `POST /v1/validate/data-access` - walidacja tokena dostepu do danych.
- `GET /admin/settings` / `PUT /admin/settings` - globalna tolerancja ryzyka.
- `PUT /admin/systems/risk` - tolerancja ryzyka dla konkretnego systemu.
- `GET /admin/ui` - GUI administratora.
- `GET /admin/blocks` / `POST /admin/blocks` / `DELETE /admin/blocks/{id}` - blokady akcji/zapytan.
- `POST /admin/agents` - tworzenie/aktualizacja agentow.
- `POST /admin/actions` - tworzenie/aktualizacja polityk akcji.
- `POST /admin/data-policies` - tworzenie/aktualizacja polityk danych.
- `POST /admin/tokens/revoke` - dynamiczne uniewaznienie tokena po `token` albo `jti`.
- `GET /admin/audit` - ostatnie zdarzenia audytu.

## Integracja Z Mini-Bankiem

Integracja idzie przez HTTP:

1. Agent pyta gateway o `action_token` dla operacji.
2. Agent albo gateway przekazuje token do `mini-bank` w naglowku, np. `Authorization: GatewayAction <token>`.
3. `mini-bank` przed wykonaniem akcji wywoluje `POST /v1/validate/action`.
4. Dla odczytow danych `mini-bank` waliduje `data_access_token` i sprawdza `tables`, `columns`, `row_filters`.

Uruchom gateway:

```bash
cd ~/Desktop/gateway
make bootstrap
make dev
```

Uruchom mini-bank w trybie gateway:

```bash
cd ~/Desktop/mini-bank
BANK_GATEWAY_URL=http://127.0.0.1:8001 python3 app.py --no-browser
```

Uruchom przykładowego agenta, który tworzy usera w banku:

```bash
cd ~/Desktop/gateway
python3 scripts/agent_to_bank_demo.py \
  --name "Jane Agent" \
  --email "jane.agent@example.com" \
  --initial-balance "25.00"
```

minibank repo: https://github.com/user0-a/mini-bank

For testing with AI Agent:
```bash
Act as an agent and test Gateway plan integrity with employee approval.

Gateway:
http://127.0.0.1:8001

Agent credentials:
x-agent-id: agent-demo
x-agent-key: demo-agent-key-please-change

Employee owner:
emp-123

Step 1:
Authorize this plan:

POST /v1/plans/authorize

Body:
{
  "plan_id": "plan-employee-demo-1",
  "goal": "Handle invoice INV-847",
  "subject": {
    "role": "admin",
    "employee_id": "emp-123"
  },
  "steps": [
    {
      "id": "s1",
      "action": "users.select",
      "params": {
        "limit": 10
      },
      "reason": "Find users related to the invoice"
    }
  ]
}

Step 2:
Try to authorize a new action outside the plan:

POST /v1/authorize

Body:
{
  "action": "customer.read",
  "params": {
    "customer_id": "CUST-123"
  },
  "subject": {
    "role": "admin",
    "employee_id": "emp-123"
  },
  "plan_id": "plan-employee-demo-1",
  "step_id": "s2"
}

Expected:
Gateway should deny with reason outside_authorized_plan.

Step 3:
Request a plan extension:

POST /v1/plans/plan-employee-demo-1/extensions

Body:
{
  "reason": "Need customer data to validate invoice ownership before continuing",
  "step": {
    "id": "s2",
    "action": "customer.read",
    "params": {
      "customer_id": "CUST-123"
    },
    "reason": "Validate customer ownership"
  }
}

Save the returned extension_id.

Step 4:
Simulate employee approval:

POST /v1/plans/extensions/{extension_id}/employee-decision

Headers:
content-type: application/json
x-employee-id: emp-123

Body:
{
  "decision": "approve",
  "comment": "I requested this task and approve the extra step"
}

Step 5:
Retry the same action:

POST /v1/authorize

Body:
{
  "action": "customer.read",
  "params": {
    "customer_id": "CUST-123"
  },
  "subject": {
    "role": "admin",
    "employee_id": "emp-123"
  },
  "plan_id": "plan-employee-demo-1",
  "step_id": "s2"
}

Expected:
Gateway should allow it and return an action_token containing plan_id, step_id, and plan_hash.

Return a short summary of each step and the key JSON responses.
```
