package org.entur.jwt.spring.auth0.context.refresh;

import static org.junit.jupiter.api.Assertions.assertNotNull;

import org.entur.jwt.junit5.AccessToken;
import org.entur.jwt.junit5.AuthorizationServer;
import org.entur.jwt.verifier.JwtVerifier;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.test.context.TestPropertySource;

import com.auth0.jwt.interfaces.DecodedJWT;

/**
 * 
 * Test for manual verification of context refresh
 *
 */

@AuthorizationServer
@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
@TestPropertySource(locations = { "/application-no-tenants.properties" })
public class RefreshSpringContext2Test {

    @Autowired
    private JwtVerifier<DecodedJWT> jwtVerifier;

    @Test
    public void testTokenIsValid1(@AccessToken(audience = "mock.my.audience") String token) throws Exception {
        System.out.println("Run " + getClass().getName());

        DecodedJWT verified = jwtVerifier.verify(token.substring(7));

        assertNotNull(verified);
    }

    @Test
    public void testTokenIsValid2(@AccessToken(audience = "mock.my.audience") String token) throws Exception {
        System.out.println("Run " + getClass().getName());

        DecodedJWT verified = jwtVerifier.verify(token.substring(7));

        assertNotNull(verified);
    }
}
