package com.wwgateway.spring;

import com.wwgateway.verifier.Json;
import jakarta.servlet.http.HttpServletRequest;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.TreeMap;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerMapping;

/**
 * Default contract:
 * <ul>
 *   <li>request with a JSON body: params = the parsed body (numbers kept exact; send money as strings);</li>
 *   <li>request without a body: params = path variables + single-valued query parameters, as strings.</li>
 * </ul>
 */
public final class DefaultGatewayParamsExtractor implements GatewayParamsExtractor {
    @Override
    public Object extract(HttpServletRequest request, HandlerMethod handler, byte[] body) {
        if (body != null && body.length > 0) {
            return Json.parse(new String(body, StandardCharsets.UTF_8));
        }
        Map<String, Object> params = new TreeMap<>();
        Object vars = request.getAttribute(HandlerMapping.URI_TEMPLATE_VARIABLES_ATTRIBUTE);
        if (vars instanceof Map<?, ?> m) m.forEach((k, v) -> params.put(String.valueOf(k), String.valueOf(v)));
        request.getParameterMap().forEach((k, v) -> {
            if (v.length != 1) throw new IllegalArgumentException("multi-valued query parameter " + k + " is not supported");
            params.put(k, v[0]);
        });
        return params;
    }
}
