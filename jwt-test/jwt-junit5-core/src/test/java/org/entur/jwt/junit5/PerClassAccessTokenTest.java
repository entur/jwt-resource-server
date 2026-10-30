package org.entur.jwt.junit5;

import com.nimbusds.jwt.JWTParser;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

import java.text.ParseException;

import static com.google.common.truth.Truth.assertThat;

/**
 * Tokens resolved before beforeEach, i.e. for the constructor (before beforeAll) and {@literal @}BeforeAll method.
 */

@AuthorizationServer
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class PerClassAccessTokenTest {

    private final String constructorToken;

    private String beforeAllToken;

    public PerClassAccessTokenTest(@AccessToken String token) {
        this.constructorToken = token;
    }

    @BeforeAll
    public void beforeAll(@AccessToken String token) {
        this.beforeAllToken = token;
    }

    @Test
    public void testIssuer(@AccessToken String token) throws ParseException {
        String issuer = getIssuer(token);

        assertThat(getIssuer(constructorToken)).isEqualTo(issuer);
        assertThat(getIssuer(beforeAllToken)).isEqualTo(issuer);
    }

    private static String getIssuer(String token) throws ParseException {
        return JWTParser.parse(token.substring(7)).getJWTClaimsSet().getIssuer();
    }
}
