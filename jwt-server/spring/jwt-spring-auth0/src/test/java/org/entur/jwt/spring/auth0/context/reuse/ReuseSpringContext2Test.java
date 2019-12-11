package org.entur.jwt.spring.auth0.context.reuse;

import static org.junit.jupiter.api.Assertions.assertNotNull;

import org.entur.jwt.spring.auth0.test.MyAccessToken;
import org.entur.jwt.spring.auth0.test.MyAuthorizationServer;
import org.entur.jwt.verifier.JwtVerifier;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.test.context.TestPropertySource;

import com.auth0.jwt.interfaces.DecodedJWT;

/**
 * 
 * Test for manual verification of context reuse
 *
 */

@MyAuthorizationServer
@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
@TestPropertySource(locations = { "/application-with-tenants.properties" })
public class ReuseSpringContext2Test {

    @Autowired
    private JwtVerifier<DecodedJWT> jwtVerifier;

    @Test
    public void testTokenIsValid1(@MyAccessToken(myId = 5) String token) throws Exception {
        System.out.println("Run " + getClass().getName());

        DecodedJWT verified = jwtVerifier.verify(token);

        assertNotNull(verified);
    }

    @Test
    public void testTokenIsValid2(@MyAccessToken(myId = 5) String token) throws Exception {
        System.out.println("Run " + getClass().getName());

        DecodedJWT verified = jwtVerifier.verify(token);

        assertNotNull(verified);
    }
}
