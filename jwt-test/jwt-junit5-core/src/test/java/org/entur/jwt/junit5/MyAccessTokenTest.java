package org.entur.jwt.junit5;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import org.entur.jwt.junit5.impl.MyAccessToken;
import org.entur.jwt.junit5.impl.MyAuthorizationServer;
import org.junit.jupiter.api.Test;

import static com.google.common.truth.Truth.assertThat;

@MyAuthorizationServer()
public class MyAccessTokenTest {

    @Test
    public void testTokenIsValid(@MyAccessToken(myId = 5) String token) throws Exception {
        JWT jwt = JWTParser.parse(token.substring(7));

        JWTClaimsSet claims = jwt.getJWTClaimsSet();

        Integer value = claims.getIntegerClaim("https://www.mock.com/organisationID");
        assertThat(value).isEqualTo(5);

    }
}
