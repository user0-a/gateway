package com.wwgateway.spring;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.method.HandlerMethod;

/**
 * Turns a request into the JSON value whose canonical hash must equal the token's params_hash.
 * The agent must authorize exactly the same value. Provide your own bean to customise.
 */
@FunctionalInterface
public interface GatewayParamsExtractor {
    Object extract(HttpServletRequest request, HandlerMethod handler, byte[] body);
}
