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

Nie ruszalem `mini-bank`. Integracja powinna isc przez HTTP:

1. Agent pyta gateway o `action_token` dla operacji.
2. Agent albo gateway przekazuje token do `mini-bank` w naglowku, np. `Authorization: GatewayAction <token>`.
3. `mini-bank` przed wykonaniem akcji wywoluje `POST /v1/validate/action`.
4. Dla odczytow danych `mini-bank` waliduje `data_access_token` i sprawdza `tables`, `columns`, `row_filters`.
