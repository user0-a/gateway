package com.wwgateway.verifier;

import java.time.Clock;
import java.util.concurrent.ConcurrentHashMap;

/** For a single instance or tests only. Clustered deployments need a shared atomic store. */
public final class InMemoryReplayStore implements ReplayStore {
    private final ConcurrentHashMap<String, Long> entries = new ConcurrentHashMap<>();
    private final Clock clock;

    public InMemoryReplayStore() { this(Clock.systemUTC()); }
    public InMemoryReplayStore(Clock clock) { this.clock = clock; }

    @Override
    public boolean add(String key, long expiresAt) {
        long now = clock.millis() / 1000;
        if (entries.size() > 10_000) entries.values().removeIf(exp -> exp <= now);
        boolean[] added = {false};
        entries.compute(key, (k, existing) -> {
            if (existing != null && existing > now) return existing;
            added[0] = true;
            return expiresAt;
        });
        return added[0];
    }
}
