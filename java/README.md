# WWGateWay — biblioteki Java

| Moduł | Zawartość | Status |
|---|---|---|
| `wwgateway-verifier-core` | Weryfikacja tokenów akcji i dostępu do danych, dowód posiadania, jednorazowość, podpisany snapshot polityki, kanoniczny JSON. Bez zależności, Java 17+. | Skompilowany i sprawdzony na wektorach z implementacji referencyjnej (Python): `VectorSuite` — wszystkie przypadki zgodne. |
| `wwgateway-spring-boot-starter` | Autokonfiguracja, `@GatewayAction`, `@GatewayDataAccess`, `GatewayPrincipal`, filtr buforujący body, `JdbcReplayStore`. | Kod gotowy, **niezbudowany jeszcze Mavenem** (brak dostępu do repozytorium Maven w środowisku, w którym powstał). Pierwszy krok: `mvn verify` i testy integracyjne MockMvc. |

```bash
cd java
mvn verify                  # buduje oba moduły, uruchamia VectorSuiteTest
```

Kontrakt parametrów (`DefaultGatewayParamsExtractor`): żądanie z ciałem JSON → parametry = całe ciało;
bez ciała → zmienne ścieżki + parametry zapytania jako tekst. Agent musi autoryzować dokładnie tę wartość.
Inny kontrakt: własny bean `GatewayParamsExtractor`.

Pojedyncze użycie tokena jest gwarantowane w klastrze tylko z `wwgateway.replay-store=jdbc` (tabela
`wwg_replay (replay_key VARCHAR(512) PRIMARY KEY, expires_at BIGINT NOT NULL)`).
