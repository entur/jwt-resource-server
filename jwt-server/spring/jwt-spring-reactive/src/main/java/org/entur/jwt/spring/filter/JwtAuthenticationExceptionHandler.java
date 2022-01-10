package org.entur.jwt.spring.filter;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;


@RestControllerAdvice
public class JwtAuthenticationExceptionHandler {

    private static final Logger logger = LoggerFactory.getLogger(JwtAuthenticationExceptionHandler.class);

    @ExceptionHandler(JwtAuthenticationServiceUnavailableException.class)
    public ResponseEntity<Object> handleHttpRequestMethodNotSupportedException(JwtAuthenticationServiceUnavailableException ex, WebRequest request) {
        logger.warn("Unable to verify token, returning service unavailable", ex);

        return new ResponseEntity<>(HttpStatus.SERVICE_UNAVAILABLE);
    }

}
