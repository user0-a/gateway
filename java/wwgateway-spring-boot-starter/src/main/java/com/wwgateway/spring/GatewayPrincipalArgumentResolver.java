package com.wwgateway.spring;

import org.springframework.core.MethodParameter;
import org.springframework.web.bind.support.WebDataBinderFactory;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.method.support.ModelAndViewContainer;

/** Injects {@link GatewayPrincipal} into controller methods protected by the gateway annotations. */
public final class GatewayPrincipalArgumentResolver implements HandlerMethodArgumentResolver {
    @Override
    public boolean supportsParameter(MethodParameter parameter) {
        return GatewayPrincipal.class.equals(parameter.getParameterType());
    }

    @Override
    public Object resolveArgument(MethodParameter parameter, ModelAndViewContainer mav, NativeWebRequest request, WebDataBinderFactory binder) {
        Object principal = request.getAttribute(GatewayPrincipal.REQUEST_ATTRIBUTE, RequestAttributes.SCOPE_REQUEST);
        if (principal == null) throw new IllegalStateException("GatewayPrincipal is only available on @GatewayAction / @GatewayDataAccess endpoints");
        return principal;
    }
}
