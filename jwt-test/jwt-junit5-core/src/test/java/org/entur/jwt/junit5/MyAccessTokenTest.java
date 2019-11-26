package org.entur.jwt.junit5;
import static com.google.common.truth.Truth.assertThat;

import java.io.IOException;

import org.entur.jwt.junit5.impl.MyAccessToken;
import org.entur.jwt.junit5.impl.MyAuthorizationServer;
import org.junit.jupiter.api.Test;

import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;

@MyAuthorizationServer()
public class MyAccessTokenTest {

	@Test
	public void testTokenIsValid(@MyAccessToken(myId = 5) String token) throws IOException {
		DecodedJWT decoded = JWT.decode(token);

		Integer value = decoded.getClaim("https://www.mock.com/organisationID").asInt();
		assertThat(value).isEqualTo(5);

	}
}
