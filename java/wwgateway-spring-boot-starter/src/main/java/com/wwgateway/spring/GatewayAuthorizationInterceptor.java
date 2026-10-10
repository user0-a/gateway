package com.wwgateway.spring;

import com.wwgateway.verifier.GatewayVerifier;
import com.wwgateway.verifier.Jcs;
import com.wwgateway.verifier.VerificationException;
import com.wwgateway.verifier.VerifiedClaims;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.util.WebUtils;

/** Verifies @GatewayAction / @GatewayDataAccess endpoints before the controller runs. Fails closed. */
public final class GatewayAuthorizationInterceptor implements HandlerInterceptor {
    public static final String PROOF_HEADER = "WWG-Proof";
    private final GatewayVerifier verifier;
    private final GatewayParamsExtractor paramsExtractor;

    public GatewayAuthorizationInterceptor(GatewayVerifier verifier, GatewayParamsExtractor paramsExtractor) {
        this.verifier = verifier;
        this.paramsExtractor = paramsExtractor;
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws IOException {
        if (!(handler instanceof HandlerMethod method)) return true;
        GatewayAction action = method.getMethodAnnotation(GatewayAction.class);
        GatewayDataAccess data = method.getMethodAnnotation(GatewayDataAccess.class);
        if (action == null && data == null) return true;
        try {
            String url = request.getRequestURL().toString();
            String proof = request.getHeader(PROOF_HEADER);
            VerifiedClaims claims;
            if (action != null) {
                String token = token(request, "GatewayAction");
                // Other filters (e.g. Spring Security) may wrap the request after CachedBodyFilter.
                CachedBodyHttpServletRequest cached = WebUtils.getNativeRequest(request, CachedBodyHttpServletRequest.class);
                // Without the cached body the controller would bind a body that was never hashed: fail closed.
                if (cached == null) throw new VerificationException("body_not_cached", "request body is not available to the gateway (CachedBodyFilter not applied)", 500);
                byte[] body = cached.body();
                Object params;
                try {
                    params = paramsExtractor.extract(request, method, body);
                } catch (RuntimeException e) {
                    throw new VerificationException("bad_request_params", "request parameters cannot be canonicalized", 400);
                }
                claims = verifier.verifyAction(token, proof, request.getMethod(), url, action.value(), params);
            } else {
                claims = verifier.verifyDataAccess(token(request, "GatewayData"), proof, request.getMethod(), url, data.table());
            }
            request.setAttribute(GatewayPrincipal.REQUEST_ATTRIBUTE, new GatewayPrincipal(claims));
            return true;
        } catch (VerificationException e) {
            reject(response, e.status(), e.code(), e.getMessage());
            return false;
        }
    }

    private static String token(HttpServletRequest request, String scheme) {
        String header = request.getHeader("Authorization");
        String prefix = scheme + " ";
        if (header == null || !header.startsWith(prefix)) throw new VerificationException("token_required", scheme + " token required", 401);
        return header.substring(prefix.length()).trim();
    }

    private static void reject(HttpServletResponse response, int status, String code, String message) throws IOException {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", code);
        body.put("message", message);
        response.setStatus(status);
        response.setContentType("application/json");
        response.getOutputStream().write(Jcs.canonicalize(body).getBytes(StandardCharsets.UTF_8));
    }
}
