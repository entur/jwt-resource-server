package org.entur.jwt.junit5;

import java.io.IOException;

import org.entur.jwt.junit5.impl.KeycloakResourceAccessToken;
import org.entur.jwt.junit5.impl.MyAuthorizationServer;
import org.junit.jupiter.api.Test;

import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import static com.google.common.truth.Truth.*;

@MyAuthorizationServer
public class KeycloakResourceAccessTokenTest {

	@Test
	public void testTokenIsValid(@KeycloakResourceAccessToken(myId = 5) String token) throws IOException {
		DecodedJWT decoded = JWT.decode(token);

		Integer value = decoded.getClaim("https://www.mock.com/organisationID").asInt();
		assertThat(value).isEqualTo(5);
	}


}