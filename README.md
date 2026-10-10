# WWGateWay — gateway autoryzacyjny dla agentów AI w banku

Agent ma intencję. Gateway nadaje uprawnienie. System banku wykonuje — tylko z ważnym tokenem.

Każda akcja agenta musi być częścią **planu zatwierdzonego przez pracownika**, dostaje **osobny,
krótkotrwały, jednorazowy token** związany z dokładnymi parametrami i z **kluczem agenta**,
a system banku weryfikuje go **lokalnie** (bez pytania gatewaya przy każdym żądaniu), z uwzględnieniem
odwołań i aktualnej polityki ryzyka.

Specyfikacja protokołu: [`docs/PROTOCOL.md`](docs/PROTOCOL.md) · Raport bezpieczeństwa:
[`docs/SECURITY_REPORT.md`](docs/SECURITY_REPORT.md) · Uruchomienie krok po kroku: [`RUNNING.md`](RUNNING.md)

## Model bezpieczeństwa

| Zagrożenie | Zabezpieczenie |
|---|---|
| Podrobienie tokena / system banku wystawia token | Podpis Ed25519 (EdDSA) kluczem gatewaya; systemy banku mają tylko klucz publiczny (JWKS) |
| Atak „alg=none” / HS256 | Akceptowany wyłącznie `EdDSA`, sprawdzany `typ`, odrzucany `crit` |
| Wyciek tokena (logi, odpowiedź agenta po prompt injection) | Token związany z kluczem agenta (`cnf.jkt`) + dowód posiadania przy każdym użyciu (na wzór DPoP, RFC 9449) |
| Ponowne użycie tokena / dowodu | Jednorazowe `jti` tokena i dowodu; każdy krok planu wykonuje się raz |
| Zmiana kwoty lub odbiorcy po autoryzacji | `params_hash` liczony z kanonicznego JSON (RFC 8785) |
| Token użyty w innym systemie / do innej akcji | `aud` = system docelowy, `action` = endpoint |
| Agent podszywa się pod pracownika lub rolę | Rola z katalogu pracowników; akcje z rolą lub ryzykiem > medium tylko w planie podpisanym przez pracownika |
| Agent rozszerza zakres zadania | `plan_hash`; akcja spoza planu → `outside_authorized_plan`, wymaga rozszerzenia zatwierdzonego przez właściciela |
| Podszycie się pod agenta / powtórzenie żądania | Żądania podpisane kluczem agenta, okno ±60 s, jednorazowy nonce |
| Zmiana polityki po wydaniu tokena | Podpisany snapshot polityki (odwołania, zawieszeni agenci, anulowane plany, tolerancja ryzyka); **fail closed** po 30 s bez świeżych danych; ochrona przed odtworzeniem starego snapshotu |
| Manipulacja audytem | Łańcuch hashy; `GET /admin/audit/verify` wykrywa zmianę i usunięcie wpisu; eksport JSON Lines do SIEM |
| Konfiguracja deweloperska na produkcji | `GATEWAY_ENV=production` odmawia startu z domyślnymi sekretami i kluczami API |
| Zalew żądań | Limit żądań na agenta |

Każde zabezpieczenie ma test, który pada, gdy zabezpieczenie zostanie wyłączone (`make mutation`).

## Szybki start

```bash
pip install -r requirements.txt
make bootstrap        # polityki, agent-demo, pracownicy emp-operator i emp-admin (klucze w .demo_keys/)
make dev              # gateway na http://127.0.0.1:8001
```

W drugim terminalu mini-bank w trybie gateway (repo `mini-bank`):

```bash
BANK_GATEWAY_URL=http://127.0.0.1:8001 python3 app.py --no-browser
```

W trzecim: `make demo` — plan → zatwierdzenie pracownika → token → wywołanie banku oraz cztery ataki
(powtórzenie tokena, skradziony token, zmiana parametrów, akcja spoza planu).

## Integracja systemu banku

**Python** (jeden plik, `sdk/python/wwg_sdk.py`):

```python
verifier = GatewayVerifier(gateway_url="https://gateway.bank", issuer="https://gateway.bank",
                           audience="core-payments", replay_store=SQLiteReplayStore("replay.db"))
claims = verifier.verify_action(token, proof, method="POST", url=request_url,
                                action="transfer.create", params=body)
```

**Java / Spring Boot** (`java/`): `wwgateway-verifier-core` (bez zależności, Java 17+) i
`wwgateway-spring-boot-starter`:

```java
@PostMapping("/transfers")
@GatewayAction("transfer.create")
public TransferResult create(@RequestBody TransferRequest body, GatewayPrincipal principal) { ... }
```

```yaml
wwgateway:
  gateway-url: https://gateway.bank
  issuer: https://gateway.bank
  audience: core-payments
  replay-store: jdbc   # pojedyncza instancja: memory
```

Weryfikator Java jest sprawdzany na wektorach wygenerowanych przez implementację referencyjną
w Pythonie (`make vectors`, `java/.../VectorSuite`).

## Najważniejsze endpointy

| Endpoint | Kto | Cel |
|---|---|---|
| `POST /v1/plans` | agent (podpis) | propozycja planu; bez tokenów |
| `POST /v1/plans/{id}/approval` | pracownik (podpis) | zatwierdzenie dokładnego `plan_hash` |
| `POST /v1/authorize` | agent (podpis) | token dla kroku planu tuż przed wykonaniem |
| `POST /v1/authorize/batch` | agent (podpis) | ocena listy akcji niskiego ryzyka |
| `POST /v1/plans/{id}/extensions` | agent (podpis) | prośba o nowy krok |
| `POST /v1/plans/extensions/{id}/employee-decision` | pracownik (podpis) | decyzja właściciela |
| `GET /.well-known/jwks.json` | publiczny | klucze publiczne gatewaya |
| `GET /v1/policy-snapshot` | publiczny | podpisane odwołania i polityka ryzyka |
| `/admin/*` | admin | polityki, ryzyko, blokady, agenci, pracownicy, rotacja kluczy, odwołania, audyt |

## Testy i dowody

```bash
make test       # testy funkcjonalne i bezpieczeństwa
make mutation   # każde zabezpieczenie wyłączone po kolei musi zostać wykryte
make bench      # opóźnienie wydania tokena i lokalnej weryfikacji
make report     # docs/SECURITY_REPORT.md z rzeczywistych uruchomień
make java-test  # moduły Java (wymaga Maven)
```

## Ograniczenia obecnej wersji (świadome)

- Stan w pliku JSON (`data/state.json`) — do demo i rozwoju; produkcja: baza danych.
- Jeden klucz administratora — produkcja: konta z rolami, SSO banku i zasada czterech oczu dla zmian polityk.
- Klucze gatewaya w plikach PEM — produkcja: HSM / KMS.
- Klucze demo agentów i pracowników generuje `bootstrap.py` — produkcja: klucz pracownika na jego urządzeniu (passkey/WebAuthn), klucz agenta w module podpisującym, poza procesem modelu.
- Starter Spring Boot nie był jeszcze uruchomiony w pełnym projekcie Spring — patrz `java/README.md`.
