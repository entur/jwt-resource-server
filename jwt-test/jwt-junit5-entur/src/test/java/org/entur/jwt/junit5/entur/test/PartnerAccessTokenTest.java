package org.entur.jwt.junit5.entur.test;
import java.io.IOException;
import org.entur.jwt.junit5.entur.test.auth0.PartnerAuth0AuthorizationServer;
import org.entur.jwt.junit5.entur.test.auth0.PartnerAuth0Token;
import org.entur.jwt.junit5.entur.test.auth0.ExpiredPartnerAuth0Token;
import org.entur.jwt.junit5.entur.test.auth0.InvalidSignaturePartnerAuth0Token;
import org.entur.jwt.junit5.entur.test.auth0.NotYetIssuedPartnerAuth0Token;
import org.entur.jwt.junit5.entur.test.auth0.UnknownAudiencePartnerAuth0Token;
import org.entur.jwt.junit5.entur.test.auth0.UnknownIssuerPartnerAuth0Token;
import org.entur.jwt.junit5.entur.test.auth0.UnknownKeyIdPartnerAuth0Token;
import org.junit.jupiter.api.Test;
import static com.google.common.truth.Truth.*;
import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;

@PartnerAuth0AuthorizationServer(namespace = "https://entur.io/")
public class PartnerAccessTokenTest {

	@Test
	public void testTokenWithOrganisation(@PartnerAuth0Token(organisationId = 5) String token) throws IOException {
		DecodedJWT decodedJWT = JWT.decode(token);
		Claim claim = decodedJWT.getClaim("https://entur.io/organisationID");

		assertThat(claim.asInt()).isEqualTo(5);
	}

	@Test
	public void testTokenWithPermissions(@PartnerAuth0Token(organisationId = 5, permissions = {"configure"}) String token) throws IOException {
		DecodedJWT decodedJWT = JWT.decode(token);
		Claim claim = decodedJWT.getClaim("permissions");

		String[] asArray = claim.asArray(String.class);
		assertThat(asArray[0]).isEqualTo("configure");
	}

	@Test
	public void testTokenIsExpired(@ExpiredPartnerAuth0Token String token) throws IOException {
		DecodedJWT decodedJWT = JWT.decode(token);
		
		Claim claim = decodedJWT.getClaim("exp"); // in seconds

		assertThat(claim.asLong()).isLessThan(System.currentTimeMillis() / 1000);
	}
	
	@Test
	public void testTokenIsNotYetIssued(@NotYetIssuedPartnerAuth0Token String token) throws IOException {
		DecodedJWT decodedJWT = JWT.decode(token);
		
		Claim claim = decodedJWT.getClaim("iat"); // in seconds

		assertThat(claim.asLong()).isGreaterThan(System.currentTimeMillis() / 1000 + Integer.MAX_VALUE / 2);
	}

	@Test
	public void testTokenSignatureInvalid(@InvalidSignaturePartnerAuth0Token String token) throws IOException {
		assertThat(token).endsWith("SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c");
	}
	
	@Test
	public void testTokenUnknownIssuer(@UnknownIssuerPartnerAuth0Token String token) throws IOException {
		DecodedJWT decodedJWT = JWT.decode(token);
		
		Claim claim = decodedJWT.getClaim("iss");

		assertThat(claim.asString()).isEqualTo("https://unknown.issuer");
	}	
	
	@Test
	public void testTokenUnknownAudience(@UnknownAudiencePartnerAuth0Token String token) throws IOException {
		DecodedJWT decodedJWT = JWT.decode(token);
		
		Claim claim = decodedJWT.getClaim("aud");

		assertThat(claim.asArray(String.class)[0]).isEqualTo("https://unknown.audience");
	}	
	
	@Test
	public void testTokenUnknownKeyId(@UnknownKeyIdPartnerAuth0Token String token) throws IOException {
		DecodedJWT decodedJWT = JWT.decode(token);
		
		assertThat(decodedJWT.getHeaderClaim("kid").asString()).isEqualTo("unknown-kid");
	}	
	
}
