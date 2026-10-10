package com.wwgateway.spring;

import com.wwgateway.verifier.ReplayStore;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.jdbc.core.JdbcTemplate;

/**
 * Cluster-safe single-use store backed by a database primary key.
 * Schema: CREATE TABLE wwg_replay (replay_key VARCHAR(512) PRIMARY KEY, expires_at BIGINT NOT NULL)
 */
public final class JdbcReplayStore implements ReplayStore {
    private final JdbcTemplate jdbc;

    public JdbcReplayStore(JdbcTemplate jdbc) { this.jdbc = jdbc; }

    @Override
    public boolean add(String key, long expiresAt) {
        long now = System.currentTimeMillis() / 1000;
        jdbc.update("DELETE FROM wwg_replay WHERE replay_key = ? AND expires_at < ?", key, now);
        try {
            return jdbc.update("INSERT INTO wwg_replay (replay_key, expires_at) VALUES (?, ?)", key, expiresAt) == 1;
        } catch (DuplicateKeyException e) {
            return false;
        }
    }
}
