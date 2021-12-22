package org.entur.jwt.spring.filter.resolver;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.function.BiFunction;
import org.entur.jwt.spring.filter.JwtAuthenticationToken;
import org.springframework.core.MethodParameter;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.support.WebDataBinderFactory;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.method.support.ModelAndViewContainer;

public class JwtArgumentResolver implements HandlerMethodArgumentResolver {

    private final List<Class<?>> paramters;
    private final BiFunction<Map<String, Object>, Class<?>, ?> transformer;

    public JwtArgumentResolver(BiFunction<Map<String, Object>, Class<?>, ?> transformer, Class<?>... parameters) {
        this(transformer, Arrays.asList(parameters));
    }

    public JwtArgumentResolver(BiFunction<Map<String, Object>, Class<?>, ?> transformer, List<Class<?>> parameters) {
        super();
        this.paramters = parameters;
        this.transformer = transformer;
    }

    @Override
    public boolean supportsParameter(MethodParameter parameter) {
        return paramters.contains(parameter.getParameterType());
    }

    @Override
    public Object resolveArgument(MethodParameter parameter, ModelAndViewContainer mavContainer, NativeWebRequest webRequest, WebDataBinderFactory binderFactory) throws Exception {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null && !(authentication instanceof AnonymousAuthenticationToken)) {
            if (authentication instanceof JwtAuthenticationToken) {
                JwtAuthenticationToken token = (JwtAuthenticationToken) authentication;

                Class<?> target = parameter.getParameterType();

                Object tenant = transformer.apply(token.getClaims(), target);

                Class<?> resolved = tenant.getClass();
                if (target.isAssignableFrom(resolved)) {
                    return tenant;
                }

                // return http 403 forbidden
                throw new UnexpectedJwtArgumentResolverResultException("Unexpected type " + resolved.getName() + " for parameter type " + target.getName());
            }
            if (parameter.isOptional()) {
                return null;
            }
            // return http 403 forbidden
            throw new JwtArgumentResolverException("Expected " + JwtAuthenticationToken.class.getName() + " authorization, was " + authentication.getClass().getName());
        }
        if (parameter.isOptional()) {
            return null;
        }
        // return http 403 forbidden
        throw new TenantExpectedAuthenticationException("Expected " + JwtAuthenticationToken.class.getName() + " authorization, was none");
    }
}