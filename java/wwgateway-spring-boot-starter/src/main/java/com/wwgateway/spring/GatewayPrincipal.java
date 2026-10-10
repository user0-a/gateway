package com.wwgateway.spring;

import com.wwgateway.verifier.VerifiedClaims;
import java.util.List;
import java.util.Map;

/** Who is acting and on whose behalf, injected into controller methods after verification. */
public final class GatewayPrincipal {
    public static final String REQUEST_ATTRIBUTE = GatewayPrincipal.class.getName();
    private final VerifiedClaims claims;

    public GatewayPrincipal(VerifiedClaims claims) { this.claims = claims; }

    public String agentId() { return claims.agentId(); }
    public String actingFor() { return claims.actingFor(); }
    public String planId() { return claims.planId(); }
    public String stepId() { return claims.stepId(); }
    public String planHash() { return claims.planHash(); }
    public String riskLevel() { return claims.riskLevel(); }
    public String tokenId() { return claims.tokenId(); }
    public Map<String, Object> claims() { return claims.asMap(); }
    public Map<String, Object> rowFilter(String table) { return claims.rowFilter(table); }
    public List<String> allowedColumns(String table) { return claims.allowedColumns(table); }
    public List<Map<String, Object>> applyDataScope(List<Map<String, Object>> rows, String table) { return claims.applyDataScope(rows, table); }
}
