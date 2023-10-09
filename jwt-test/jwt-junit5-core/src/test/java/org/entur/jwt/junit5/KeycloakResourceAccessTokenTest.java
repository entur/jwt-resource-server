package org.entur.jwt.junit5;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import org.entur.jwt.junit5.impl.KeycloakResourceAccessToken;
import org.entur.jwt.junit5.impl.MyAuthorizationServer;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.text.ParseException;

import static com.google.common.truth.Truth.assertThat;

@MyAuthorizationServer
public class KeycloakResourceAccessTokenTest {

    @Test
    public void testTokenIsValid(@KeycloakResourceAccessToken(myId = 5) String token) throws IOException, ParseException {
        JWT jwt = JWTParser.parse(token.substring(7));

        JWTClaimsSet claims = jwt.getJWTClaimsSet();

        Integer value = claims.getIntegerClaim("https://www.mock.com/organisationID");
        assertThat(value).isEqualTo(5);
    }

}