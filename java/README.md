# WWGateWay — biblioteki Java

| Moduł | Zawartość | Status |
|---|---|---|
| `wwgateway-verifier-core` | Weryfikacja tokenów akcji i dostępu do danych, dowód posiadania, jednorazowość, podpisany snapshot polityki, kanoniczny JSON. Bez zależności, Java 17+. | Skompilowany i sprawdzony na wektorach z implementacji referencyjnej (Python): `VectorSuite` — wszystkie przypadki zgodne. |
| `wwgateway-spring-boot-starter` | Autokonfiguracja, `@GatewayAction`, `@GatewayDataAccess`, `GatewayPrincipal`, filtr buforujący body, `JdbcReplayStore`. | Zbudowany Mavenem (Spring Boot 3.3.5, JDK 21). `GatewayStarterIT` (MockMvc): każdy wektor akcji jako żądanie HTTP — kod HTTP, kod błędu, kontroler nie wykonany przy odrzuceniu; brak tokenu, zakres danych, limit body (413), wrappery żądań, endpointy bez adnotacji, warunki autokonfiguracji, `JdbcReplayStore` na H2. `NoSpringJdbcIT`: start bez spring-jdbc na classpath. |
| `wwgateway-spring-example` | Przykładowy serwis płatności (`core-payments`, port 8002) ze `replay-store=jdbc` na H2 i agentem demo w Pythonie. | Sprawdzony z działającym gatewayem — patrz [`wwgateway-spring-example/README.md`](wwgateway-spring-example/README.md). |

```bash
cd java
mvn -B verify               # wszystkie moduły: VectorSuiteTest, testy integracyjne startera (failsafe), test przykładu
```

Kontrakt parametrów (`DefaultGatewayParamsExtractor`): żądanie z ciałem JSON → parametry = całe ciało;
bez ciała → zmienne ścieżki + parametry zapytania jako tekst. Agent musi autoryzować dokładnie tę wartość.
Inny kontrakt: własny bean `GatewayParamsExtractor`.

Pojedyncze użycie tokena jest gwarantowane w klastrze tylko z `wwgateway.replay-store=jdbc` (tabela
`wwg_replay (replay_key VARCHAR(512) PRIMARY KEY, expires_at BIGINT NOT NULL)`). Bez `DataSource`/`JdbcTemplate`
ustawienie `jdbc` zatrzymuje start aplikacji (brak cichego powrotu do pamięci).

`CachedBodyFilter` musi obejmować chronione endpointy (rejestrowany automatycznie). Jeśli interceptor nie znajdzie
zbuforowanego body (także pod wrapperami innych filtrów, np. Spring Security), żądanie jest odrzucane: `500 body_not_cached`.
