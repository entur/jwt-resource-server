package org.entur.jwt.spring.filter.resolver;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.function.BiFunction;
import org.entur.jwt.spring.filter.JwtAuthenticationToken;
import org.springframework.core.MethodParameter;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.web.reactive.BindingContext;
import org.springframework.web.reactive.result.method.HandlerMethodArgumentResolver;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

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
    public Mono<Object> resolveArgument(MethodParameter parameter, BindingContext bindingContext, ServerWebExchange exchange) {
        return ReactiveSecurityContextHolder.getContext()
            .map(SecurityContext::getAuthentication)
            .switchIfEmpty(Mono.defer(() -> {
                if (parameter.isOptional()) {
                    return Mono.empty();
                }

                throw new TenantExpectedAuthenticationException("Expected " + JwtAuthenticationToken.class.getName() + " authorization, was none");
                }))
            .map(authentication -> {
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
                        return Mono.empty();
                    }
                    // return http 403 forbidden
                    throw new JwtArgumentResolverException("Expected " + JwtAuthenticationToken.class.getName() + " authorization, was " + authentication.getClass().getName());
                }
                if (parameter.isOptional()) {
                    return Mono.empty();
                }
                // return http 403 forbidden
                throw new TenantExpectedAuthenticationException("Expected " + JwtAuthenticationToken.class.getName() + " authorization, was none");
            });
    }

}
