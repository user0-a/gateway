package com.wwgateway.spring;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Protects a controller method: the request must carry {@code Authorization: GatewayAction <token>}
 * and {@code WWG-Proof: <proof>}, the token must authorize exactly {@link #value()} with exactly the
 * parameters of this request (see {@link GatewayParamsExtractor}), and it is consumed (single use).
 */
@Documented
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.METHOD)
public @interface GatewayAction {
    /** Action id as registered in the gateway, e.g. "transfer.create". */
    String value();
}
