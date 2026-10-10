package com.wwgateway.verifier;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/** Claims of a verified token plus helpers to apply a data-access scope. */
public final class VerifiedClaims {
    private final Map<String, Object> claims;

    public VerifiedClaims(Map<String, Object> claims) { this.claims = Collections.unmodifiableMap(claims); }

    public Map<String, Object> asMap() { return claims; }
    public String agentId() { return (String) claims.get("sub"); }
    public String actingFor() { return claims.get("act_for") instanceof String s ? s : null; }
    public String action() { return (String) claims.get("action"); }
    public String planId() { return claims.get("plan_id") instanceof String s ? s : null; }
    public String stepId() { return claims.get("step_id") instanceof String s ? s : null; }
    public String planHash() { return claims.get("plan_hash") instanceof String s ? s : null; }
    public String riskLevel() { return (String) claims.get("risk_level"); }
    public String tokenId() { return (String) claims.get("jti"); }

    /** Equality row filters for a table, e.g. {"owner": "Jane"}; empty map = no filter. */
    public Map<String, Object> rowFilter(String table) {
        if (claims.get("row_filters") instanceof Map<?, ?> all && all.get(table) instanceof Map<?, ?> f) {
            Map<String, Object> out = new LinkedHashMap<>();
            f.forEach((k, v) -> out.put(String.valueOf(k), v));
            return out;
        }
        return Map.of();
    }

    /** Allowed columns for a table, or null when the token does not restrict columns. */
    public List<String> allowedColumns(String table) {
        if (claims.get("columns") instanceof Map<?, ?> all && all.get(table) instanceof Collection<?> c) {
            List<String> out = new ArrayList<>();
            c.forEach(x -> out.add(String.valueOf(x)));
            return out;
        }
        return null;
    }

    /** Applies row filters and the column allow-list (same semantics as Python apply_data_scope). */
    public List<Map<String, Object>> applyDataScope(List<Map<String, Object>> rows, String table) {
        Map<String, Object> filter = rowFilter(table);
        List<String> columns = allowedColumns(table);
        List<Map<String, Object>> out = new ArrayList<>();
        for (Map<String, Object> row : rows) {
            boolean match = filter.entrySet().stream().allMatch(e -> Objects.equals(String.valueOf(row.get(e.getKey())), String.valueOf(e.getValue())));
            if (!match) continue;
            Map<String, Object> projected = new LinkedHashMap<>();
            row.forEach((k, v) -> { if (columns == null || columns.contains(k)) projected.put(k, v); });
            out.add(projected);
        }
        return out;
    }
}
