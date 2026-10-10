CREATE TABLE IF NOT EXISTS wwg_replay (
    replay_key VARCHAR(512) PRIMARY KEY,
    expires_at BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS payments (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    from_account VARCHAR(64) NOT NULL,
    to_account VARCHAR(64) NOT NULL,
    amount DECIMAL(19, 2) NOT NULL,
    title VARCHAR(255),
    agent_id VARCHAR(100) NOT NULL,
    acting_for VARCHAR(100),
    plan_id VARCHAR(100),
    step_id VARCHAR(100),
    token_id VARCHAR(100) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
