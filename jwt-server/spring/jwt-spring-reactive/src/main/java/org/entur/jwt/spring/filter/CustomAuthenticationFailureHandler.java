package org.entur.jwt.spring.filter;

import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.server.ServerAuthenticationEntryPoint;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.authentication.ServerAuthenticationFailureHandler;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

@Component
public class CustomAuthenticationFailureHandler implements ServerAuthenticationFailureHandler {

    @Override
    public Mono<Void> onAuthenticationFailure(WebFilterExchange exchange, AuthenticationException exception) {
        return Mono.fromRunnable(() -> {
            ServerHttpResponse response = exchange.getExchange().getResponse();
            response.setStatusCode(HttpStatus.FORBIDDEN);
        });
    }
}
