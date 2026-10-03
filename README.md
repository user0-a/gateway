# WWGateWaySolution MVP

Serwis autoryzacyjny dla agentow AI. Agent wysyla zamiar wykonania akcji, gateway go uwierzytelnia, autoryzuje i wystawia krotkotrwale tokeny:

- `action_token` - dla konkretnej akcji, np. `user.create`, `transfer.create`.
- `data_access_token` - dla dostepu do konkretnych tabel, kolumn i filtrow wierszy.

Docelowy serwis, np. `mini-bank`, nie ufa agentowi. Przed wykonaniem operacji zuzywa jednorazowy token w gatewayu, ktory sprawdza akcje, system, operacje i hash rzeczywistych parametrow.

## Flow Systemu

1. Pracownik banku prosi agenta o wykonanie pracy.
2. Agent uklada liste akcji, np. `users.select`, `records.delete`, `transfer.create`.
3. Agent wysyla akcje wraz z mandatem, celem biznesowym i identyfikatorem zadania.
4. Gateway niezaleznie uwierzytelnia agenta i pracownika oraz sprawdza mandat, role, limity, destination, polityki i ryzyko.
5. Decyzja to `allow`, `require_approval` albo `deny`.
6. Po `allow` gateway wystawia krotkotrwaly token zwiazany z dokladnymi parametrami.
7. Serwis docelowy wywoluje `POST /v1/consume/action`; poprawny token moze zostac zuzyty tylko raz.

## Zakres MVP

- oddzielna tozsamosc agenta i pracownika,
- delegowane mandaty pracownik-agent,
- cele biznesowe, limity finansowe i allowlista destination,
- human-in-the-loop approval dla wybranych poziomow ryzyka,
- tokeny zwiazane z hashem parametrow i jednorazowe zuzycie,
- centralne blokady, risk tolerance, revocation i audit log,
- Admin Hub z kolejka approvals i podgladem mandatow.

MVP uzywa pliku JSON, kluczy demonstracyjnych i HMAC. Wdrozenie bankowe wymaga zewnetrznego IdP, PostgreSQL/Redis, KMS/HSM i niezmiennego audytu.

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
- zatwierdzac lub odrzucac operacje wymagajace decyzji czlowieka,
- podejrzec mandaty, akcje, systemy i aktywne blokady.

Panel pyta o `admin key` i wysyla go jako `x-admin-key` do admin API.

## Uruchomienie

Linux/macOS:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
make dev
```

Windows PowerShell:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python scripts\bootstrap.py
python -m uvicorn gateway.app:app --reload --host 127.0.0.1 --port 8001
```

Testy na Windows uruchomisz poleceniem:

```powershell
python -m pytest -q
```

Pelny scenariusz demonstracyjny, przy uruchomionym serwerze:

```powershell
python scripts\demo_flow.py
```

Domyslne zmienne dev:

- `GATEWAY_ADMIN_KEY=dev-admin-key`
- `GATEWAY_TOKEN_SECRET=dev-change-me`
- `GATEWAY_STATE=data/state.json`

W realnym srodowisku ustaw je samodzielnie.

## Szybki Start

Zaladuj przykladowe polityki, agenta, pracownika i mandat:

```bash
make bootstrap
```

Popros gateway o token akcji i token dostepu do danych:

```bash
curl -s http://127.0.0.1:8001/v1/authorize \
  -H 'content-type: application/json' \
  -H 'x-agent-id: agent-demo' \
  -H 'x-agent-key: demo-agent-key-please-change' \
  -H 'x-employee-id: employee-demo' \
  -H 'x-employee-key: demo-employee-key-please-change' \
  -d '{
    "request_id": "demo-transfer-001",
    "action": "transfer.create",
    "params": {"from_account": "ACC-1", "to_account": "ACC-2", "amount": 100},
    "data_policy": "accounts-read-basic",
    "purpose_code": "customer-payment",
    "reason": "demo transfer",
    "mandate_id": "mandate-demo"
  }'
```

Popros gateway o tokeny dla listy akcji:

```bash
curl -s http://127.0.0.1:8001/v1/authorize/batch \
  -H 'content-type: application/json' \
  -H 'x-agent-id: agent-demo' \
  -H 'x-agent-key: demo-agent-key-please-change' \
  -H 'x-employee-id: employee-demo' \
  -H 'x-employee-key: demo-employee-key-please-change' \
  -d '{
    "actions": [
      {"request_id":"demo-read-001","action":"users.select","params":{"limit":10},"purpose_code":"customer-support","mandate_id":"mandate-demo"},
      {"request_id":"demo-delete-001","action":"records.delete","params":{"record_count":300},"purpose_code":"data-retention","mandate_id":"mandate-demo"}
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

Jednorazowe zuzycie tokena przez serwis wykonawczy:

```bash
curl -s http://127.0.0.1:8001/v1/consume/action \
  -H 'content-type: application/json' \
  -d '{"token":"PASTE_TOKEN_HERE","action":"transfer.create","service":"mini-bank","operation":"transfer.create","params":{"from_account":"ACC-1","to_account":"ACC-2","amount":100}}'
```

## Glowne Endpointy

- `POST /v1/authorize` - agent prosi o autoryzacje akcji.
- `POST /v1/authorize/batch` - agent prosi o tokeny dla listy akcji.
- `POST /v1/introspect` - sprawdzenie dowolnego tokena.
- `POST /v1/validate/action` - walidacja tokena akcji.
- `POST /v1/consume/action` - sprawdzenie parametrow i atomowe, jednorazowe zuzycie tokena.
- `POST /v1/validate/data-access` - walidacja tokena dostepu do danych.
- `GET /admin/settings` / `PUT /admin/settings` - globalna tolerancja ryzyka.
- `PUT /admin/systems/risk` - tolerancja ryzyka dla konkretnego systemu.
- `GET /admin/ui` - GUI administratora.
- `GET /admin/blocks` / `POST /admin/blocks` / `DELETE /admin/blocks/{id}` - blokady akcji/zapytan.
- `POST /admin/agents` - tworzenie/aktualizacja agentow.
- `GET/POST /admin/employees` - zarzadzanie demonstracyjnymi tozsamosciami pracownikow.
- `GET/POST /admin/mandates` - zarzadzanie delegowanymi mandatami.
- `GET /admin/approvals` - kolejka decyzji human-in-the-loop.
- `POST /admin/approvals/{id}/approve` / `deny` - decyzja approvera.
- `POST /admin/actions` - tworzenie/aktualizacja polityk akcji.
- `POST /admin/data-policies` - tworzenie/aktualizacja polityk danych.
- `POST /admin/tokens/revoke` - dynamiczne uniewaznienie tokena po `token` albo `jti`.
- `GET /admin/audit` - ostatnie zdarzenia audytu.

## Integracja Z Mini-Bankiem

Nie ruszalem `mini-bank`. Integracja powinna isc przez HTTP:

1. Agent pyta gateway o `action_token` dla operacji.
2. Agent albo gateway przekazuje token do `mini-bank` w naglowku, np. `Authorization: GatewayAction <token>`.
3. `mini-bank` przed wykonaniem akcji wywoluje `POST /v1/consume/action` z tokenem i rzeczywistymi parametrami.
4. Dla odczytow danych `mini-bank` waliduje `data_access_token` i sprawdza `tables`, `columns`, `row_filters`.
