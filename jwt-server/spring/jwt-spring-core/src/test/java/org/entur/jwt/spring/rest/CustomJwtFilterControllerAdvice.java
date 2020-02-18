package org.entur.jwt.spring.rest;

import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Profile;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

/**
 * 
 * Example of using an controller advice to return a custom message on token authentication problems.
 * 
 */

@Profile("controllerAdvice")
@ControllerAdvice
public class CustomJwtFilterControllerAdvice {

    public static final String CONTROLLER_ADVICE = "Controller-Advice";
	private static Logger log = LoggerFactory.getLogger(CustomJwtFilterControllerAdvice.class);

    @ExceptionHandler(value = BadCredentialsException.class)
    public void defaultErrorHandler(HttpServletResponse response, BadCredentialsException e) throws Exception {
       log.info("Handle via controller advice", e);
       response.setStatus(HttpStatus.UNAUTHORIZED.value());
       response.setHeader(CONTROLLER_ADVICE, "true");
    }
}