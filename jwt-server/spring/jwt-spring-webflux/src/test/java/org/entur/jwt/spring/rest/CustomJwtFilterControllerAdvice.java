package org.entur.jwt.spring.rest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Profile;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.server.ServerWebExchange;

/**
 *
 * Example of using an controller advice to return a custom message on token authentication problems.
 *
 */

@Profile("controllerAdvice")
@RestControllerAdvice
public class CustomJwtFilterControllerAdvice {

    public static final String CONTROLLER_ADVICE = "Controller-Advice";
    private static Logger log = LoggerFactory.getLogger(CustomJwtFilterControllerAdvice.class);

    @ExceptionHandler(value = BadCredentialsException.class)
    public void defaultErrorHandler(ServerWebExchange exchange, BadCredentialsException e) {
       log.info("Handle via controller advice", e);
       exchange.getResponse().setRawStatusCode(HttpStatus.UNAUTHORIZED.value());
       exchange.getResponse().getHeaders().add(CONTROLLER_ADVICE, "true");
    }
}
