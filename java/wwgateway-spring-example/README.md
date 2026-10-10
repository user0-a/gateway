# wwgateway-spring-example — payments service protected by the starter

A minimal Spring Boot service (`core-payments`, port 8002) with one protected endpoint:

```java
@PostMapping("/payments")
@GatewayAction("payment.create")
public Map<String, Object> create(@RequestBody PaymentRequest body, GatewayPrincipal principal) { ... }
```

Configuration (`src/main/resources/application.yml`):

```yaml
wwgateway:
  gateway-url: ${WWG_GATEWAY_URL:http://127.0.0.1:8001}
  issuer: ${WWG_ISSUER:wwgateway-dev}
  audience: core-payments      # token "aud" = the action's "service" in the gateway
  replay-store: jdbc           # table wwg_replay, created by schema.sql (H2 in memory here)
```

`GET /health` has no annotation and is not touched by the gateway.

## Run it with the Python demo agent (Windows commands; on Linux/macOS use `source .venv/bin/activate`)

Terminal 1, gateway (from the `gateway` repository root):

```bat
.venv\Scripts\activate
python scripts\bootstrap.py
uvicorn gateway.app:app --host 127.0.0.1 --port 8001
```

Terminal 2, this service:

```bat
cd java
mvn -B package
java -jar wwgateway-spring-example\target\wwgateway-spring-example-0.2.0.jar
```

Terminal 3, the agent:

```bat
.venv\Scripts\activate
python java\wwgateway-spring-example\agent_demo.py --attacks
```

`agent_demo.py` first registers the action `payment.create` (service `core-payments`, `requires_plan: true`)
through the admin API and allows `agent-demo` to request it. It then proposes a plan, has `emp-operator`
approve the exact plan hash, gets a token for step `s1`, and calls `POST /payments` with the token and a
proof of possession. Output of a real run:

```
[200] Agent proposes a plan
[200] Employee approves the exact plan hash
[200] Agent gets the token for step s1                       sender_constrained: True
[201] Spring payments service executes the payment          agent-demo acting for emp-operator, plan step s1
[401] ATTACK: replay the same token                          token_replay
[401] ATTACK: stolen token without the agent key             proof_key_mismatch
[403] ATTACK: change the amount after authorization          params_mismatch
```

The agent calls the service exactly like mini-bank: `Authorization: GatewayAction <token>` plus
`WWG-Proof: <proof>` (`AgentClient.proof("POST", url, token)`), with the JSON body equal to the
authorized `params` (send amounts as strings).
