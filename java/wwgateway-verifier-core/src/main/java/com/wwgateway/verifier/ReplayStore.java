package com.wwgateway.verifier;

/**
 * Single-use registry. {@code add} must be ATOMIC across all instances of the service
 * (use Redis SET NX EX or a database primary key in production).
 */
public interface ReplayStore {
    /** @return false if the key already exists and has not expired (= replay). */
    boolean add(String key, long expiresAtEpochSeconds);
}
