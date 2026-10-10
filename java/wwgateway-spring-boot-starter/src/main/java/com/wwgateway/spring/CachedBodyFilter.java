package com.wwgateway.spring;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.web.filter.OncePerRequestFilter;

/** Caches request bodies (bounded) so the gateway interceptor can bind them to the token. */
public final class CachedBodyFilter extends OncePerRequestFilter {
    private final int maxBytes;

    public CachedBodyFilter(int maxBytes) { this.maxBytes = maxBytes; }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws ServletException, IOException {
        if (request instanceof CachedBodyHttpServletRequest) {
            chain.doFilter(request, response);
            return;
        }
        CachedBodyHttpServletRequest wrapped;
        try {
            wrapped = new CachedBodyHttpServletRequest(request, maxBytes);
        } catch (IOException e) {
            response.sendError(HttpServletResponse.SC_REQUEST_ENTITY_TOO_LARGE);
            return;
        }
        chain.doFilter(wrapped, response);
    }
}
