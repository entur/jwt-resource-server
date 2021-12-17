package org.entur.jwt.spring.rest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Profile;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.server.authentication.HttpBasicServerAuthenticationEntryPoint;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Profile("customEntryPoint")
@Component
public class CustomServerAuthenticationEntryPoint extends HttpBasicServerAuthenticationEntryPoint {

    public static final String ENTRY_POINT = "Entry-Point";
    private static Logger log = LoggerFactory.getLogger(CustomServerAuthenticationEntryPoint.class);

    @Override
    public Mono<Void> commence(ServerWebExchange exchange, AuthenticationException ex) {
        return Mono.fromRunnable(() -> {
                log.info("Handle via controller advice", ex);
                exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                exchange.getResponse().getHeaders().add(ENTRY_POINT, "true");
        });
    }
}
