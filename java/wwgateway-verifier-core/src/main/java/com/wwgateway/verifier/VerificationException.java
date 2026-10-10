package com.wwgateway.verifier;

/** Stable machine-readable {@code code} (same codes as the Python SDK) plus the HTTP status to return. */
public class VerificationException extends RuntimeException {
    private static final long serialVersionUID = 1L;
    private final String code;
    private final int status;

    public VerificationException(String code, String message, int status) {
        super(message);
        this.code = code;
        this.status = status;
    }

    public String code() { return code; }
    public int status() { return status; }
}
