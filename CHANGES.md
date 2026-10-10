# Zmiany w wersji 0.2 (bezpieczeństwo tokenów i integracja z bankiem)

## Breaking changes

| Było | Jest | Dlaczego |
|---|---|---|
| Tokeny HMAC ze wspólnym sekretem `GATEWAY_TOKEN_SECRET` | JWS EdDSA (Ed25519), `kid`, rotacja, JWKS | System banku nie może już podrobić tokena |
| Bank pyta gateway o każdy token (`/v1/validate/*`) | Bank weryfikuje lokalnie (`wwg_sdk.py` / Java), `/v1/validate/*` usunięte | Brak wąskiego gardła i pojedynczego punktu awarii |
| Token działa w rękach każdego, kto go ma | Token związany z kluczem agenta + nagłówek `WWG-Proof` | Wyciek tokena nic nie daje |
| Token wielokrotnego użytku | Jednorazowy; każdy krok planu wykonuje się raz | Brak powtórzeń i podwójnych płatności |
| Agent uwierzytelniany stałym `x-agent-key` | Żądania podpisane kluczem agenta (`x-agent-*`); klucze API tylko w trybie deweloperskim, przechowywane jako hash | |
| `POST /v1/plans/authorize` od razu wydawał tokeny, plan zatwierdzał sam agent | Plan czeka na podpis pracownika (`POST /v1/plans/{id}/approval`), tokeny wydawane krok po kroku przez `/v1/authorize` | Wstrzyknięty krok nie przejdzie bez zgody człowieka |
| Pracownik identyfikowany nagłówkiem `x-employee-id` | Katalog pracowników z kluczami; decyzje podpisane (`x-employee-*`) | Nagłówek mógł podać każdy |
| Rola (`subject.role`) podawana przez agenta | Rola z katalogu pracowników; akcje z rolą lub ryzykiem > medium tylko w zatwierdzonym planie | Agent mógł nadać sobie rolę admina |
| `/v1/introspect` publiczny | Tylko z kluczem admina | Wyciek claimów |
| Audyt obcinany do 1000 wpisów, bez ochrony | Łańcuch hashy, weryfikacja, eksport JSON Lines | Wykrywalna manipulacja |
| Panel admina z wpisanym kluczem `dev-admin-key` | Puste pole; tryb produkcyjny odmawia startu z sekretami deweloperskimi | |
| Strona `/demo` (agent w przeglądarce z kluczem API) | Usunięta; demo: `make demo` | Przeglądarka trzymała klucz agenta i podawała rolę |
| Mini-bank: odczyty bez ochrony | Odczyty z `GatewayData` (tabele, kolumny, wiersze); `BANK_PROTECT_READS=0` wyłącza | |

## Nowe

- Podpisany snapshot polityki (`/v1/policy-snapshot`): odwołane tokeny, zawieszeni agenci, anulowane plany, tolerancja ryzyka; fail closed; ochrona przed odtworzeniem starego snapshotu.
- `POST /admin/agents/{id}/suspend`, `POST /admin/plans/{id}/cancel`, `POST /admin/employees`, `POST /admin/keys/rotate`, `POST /admin/keys/{kid}/retire`, `GET /admin/audit/verify`, `GET /admin/audit/export`.
- Limit żądań na agenta, limit ponownego wydania tokena dla kroku planu, plany wygasają (`GATEWAY_PLAN_TTL`).
- `sdk/python/wwg_sdk.py`: klient agenta i weryfikator dla systemów banku (jeden plik).
- `java/`: weryfikator bez zależności + starter Spring Boot.
- `docs/PROTOCOL.md`, `docs/SECURITY_REPORT.md`, `tools/mutation_check.py`, `tools/benchmark.py`, `tools/make_java_vectors.py`, CI.

## Poprawki startera Spring po pierwszym buildzie Mavenem

- Interceptor szuka zbuforowanego body także pod wrapperami innych filtrów (`WebUtils.getNativeRequest`); wcześniej
  każdy wrapper (np. Spring Security) powodował `params_mismatch` dla każdego żądania. Brak zbuforowanego body →
  `500 body_not_cached` (wcześniej parametry liczone bez body, a kontroler wiązał niezweryfikowane body).
- Autokonfiguracja ładuje się po `JdbcTemplateAutoConfiguration`; wcześniej `replay-store=jdbc` nigdy nie znajdował
  `JdbcTemplate` i aplikacja nie startowała.
- Testy integracyjne (`GatewayStarterIT`, `NoSpringJdbcIT`, failsafe) i moduł `wwgateway-spring-example`.
- `tools/security_report.py` uruchamia pełne `mvn -B verify` (także na Windows).
