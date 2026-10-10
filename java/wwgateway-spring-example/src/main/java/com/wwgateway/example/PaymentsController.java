package com.wwgateway.example;

import com.wwgateway.spring.GatewayAction;
import com.wwgateway.spring.GatewayPrincipal;
import java.math.BigDecimal;
import java.util.LinkedHashMap;
import java.util.Map;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.support.GeneratedKeyHolder;
import org.springframework.jdbc.support.KeyHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

@RestController
public class PaymentsController {
    /** Exactly the JSON the agent authorized; amounts travel as strings ("120.00"). */
    public record PaymentRequest(String from_account, String to_account, String amount, String title) {}

    private final JdbcTemplate jdbc;

    public PaymentsController(JdbcTemplate jdbc) { this.jdbc = jdbc; }

    @PostMapping("/payments")
    @GatewayAction("payment.create")
    @ResponseStatus(HttpStatus.CREATED)
    public Map<String, Object> create(@RequestBody PaymentRequest body, GatewayPrincipal principal) {
        BigDecimal amount;
        try {
            amount = new BigDecimal(body.amount());
        } catch (RuntimeException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "amount must be a decimal string");
        }
        KeyHolder key = new GeneratedKeyHolder();
        jdbc.update(con -> {
            var ps = con.prepareStatement(
                    "INSERT INTO payments (from_account, to_account, amount, title, agent_id, acting_for, plan_id, step_id, token_id) VALUES (?,?,?,?,?,?,?,?,?)",
                    new String[] {"id"});
            ps.setString(1, body.from_account());
            ps.setString(2, body.to_account());
            ps.setBigDecimal(3, amount);
            ps.setString(4, body.title());
            ps.setString(5, principal.agentId());
            ps.setString(6, principal.actingFor());
            ps.setString(7, principal.planId());
            ps.setString(8, principal.stepId());
            ps.setString(9, principal.tokenId());
            return ps;
        }, key);
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("id", key.getKey().longValue());
        out.put("status", "accepted");
        out.put("amount", body.amount());
        out.put("agent", principal.agentId());
        out.put("acting_for", principal.actingFor());
        out.put("plan_id", principal.planId());
        out.put("step_id", principal.stepId());
        return out;
    }

    /** Not annotated: untouched by the gateway. */
    @GetMapping("/health")
    public Map<String, Object> health() { return Map.of("status", "ok"); }
}
