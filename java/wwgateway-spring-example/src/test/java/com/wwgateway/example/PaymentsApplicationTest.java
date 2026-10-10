package com.wwgateway.example;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.wwgateway.spring.JdbcReplayStore;
import com.wwgateway.verifier.ReplayStore;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.web.servlet.MockMvc;

/** Wiring only (no gateway running): the full token flow is exercised by agent_demo.py against a live gateway. */
@SpringBootTest
@AutoConfigureMockMvc
class PaymentsApplicationTest {
    @Autowired MockMvc mvc;
    @Autowired ReplayStore replayStore;
    @Autowired JdbcTemplate jdbc;

    @Test
    void usesTheJdbcReplayStore() {
        assertThat(replayStore).isInstanceOf(JdbcReplayStore.class);
        long now = System.currentTimeMillis() / 1000;
        assertThat(replayStore.add("test:once", now + 60)).isTrue();
        assertThat(replayStore.add("test:once", now + 60)).isFalse();
    }

    @Test
    void paymentsRequireAGatewayToken() throws Exception {
        mvc.perform(post("/payments").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"from_account\":\"A\",\"to_account\":\"B\",\"amount\":\"1.00\",\"title\":\"t\"}"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("token_required"));
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM payments", Integer.class)).isZero();
    }

    @Test
    void healthIsNotProtected() throws Exception {
        mvc.perform(get("/health")).andExpect(status().isOk()).andExpect(jsonPath("$.status").value("ok"));
    }
}
