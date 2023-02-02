package org.entur.jwt.client.spring;

import org.entur.jwt.client.spring.classic.RestTemplateJwtClientAutoConfiguration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@RestController
public class DummyRestController {

    private static final Logger log = LoggerFactory.getLogger(DummyRestController.class);

    @GetMapping("/invalidCookie")
    public ResponseEntity unprotected(HttpServletResponse response) {
        log.info("Get method with invalid cookie");

        Cookie cookie = new Cookie("__cf_bm", "ABCDEF");
        cookie.setDomain("eu.auth0.com");
        cookie.setPath("/");
        cookie.setVersion(0);
        cookie.setMaxAge(100);
        response.addCookie(cookie);

        HttpHeaders httpHeaders = new HttpHeaders();
        return new ResponseEntity<>("{}", httpHeaders, HttpStatus.OK);
    }

}
