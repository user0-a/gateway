package com.wwgateway.spring;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Protects a read: the request must carry {@code Authorization: GatewayData <data_access_token>}
 * granting {@link #table()}. Use {@link GatewayPrincipal#rowFilter(String)} and
 * {@link GatewayPrincipal#applyDataScope} to restrict rows and columns.
 */
@Documented
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.METHOD)
public @interface GatewayDataAccess {
    String table();
}
