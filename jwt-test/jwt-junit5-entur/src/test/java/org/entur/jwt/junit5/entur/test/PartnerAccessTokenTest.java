package org.entur.jwt.junit5.entur.test;

import com.nimbusds.jose.Header;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import org.entur.jwt.junit5.claim.MissingClaim;
import org.entur.jwt.junit5.entur.test.auth0.ExpiredPartnerAuth0Token;
import org.entur.jwt.junit5.entur.test.auth0.InvalidSignaturePartnerAuth0Token;
import org.entur.jwt.junit5.entur.test.auth0.NotYetIssuedPartnerAuth0Token;
import org.entur.jwt.junit5.entur.test.auth0.PartnerAuth0AuthorizationServer;
import org.entur.jwt.junit5.entur.test.auth0.PartnerAuth0Token;
import org.entur.jwt.junit5.entur.test.auth0.UnknownAudiencePartnerAuth0Token;
import org.entur.jwt.junit5.entur.test.auth0.UnknownIssuerPartnerAuth0Token;
import org.entur.jwt.junit5.entur.test.auth0.UnknownKeyIdPartnerAuth0Token;
import org.junit.jupiter.api.Test;

import java.text.ParseException;

import static com.google.common.truth.Truth.assertThat;

@PartnerAuth0AuthorizationServer(namespace = "https://entur.io/")
public class PartnerAccessTokenTest {

    @Test
    public void testTokenWithOrganisation(@PartnerAuth0Token(organisationId = 5) String token) throws Exception {
        JWT jwt = JWTParser.parse(token.substring(7));

        JWTClaimsSet claims = jwt.getJWTClaimsSet();

        int id = claims.getIntegerClaim("https://entur.io/organisationID");

        assertThat(id).isEqualTo(5);
    }

    @Test
    public void testTokenWithConvenienceAttributes(@PartnerAuth0Token(organisationId = 5, audience = "https://myAudience", subject = "mySubject") String token) throws Exception {
        JWTClaimsSet decodedJWT = decode(token);
        String[] asArray = decodedJWT.getStringArrayClaim("aud");

        assertThat(asArray[0]).isEqualTo("https://myAudience");

        String subject = decodedJWT.getStringClaim("sub");
        assertThat(subject).isEqualTo("mySubject");

    }

    @Test
    public void testTokenWithPermissions(@PartnerAuth0Token(organisationId = 5, permissions = {"configure"}) String token) throws Exception {
        JWTClaimsSet decodedJWT = decode(token);
        String[] asArray = decodedJWT.getStringArrayClaim("permissions");

        assertThat(asArray[0]).isEqualTo("configure");
    }

    @Test
    public void testTokenIsExpired(@ExpiredPartnerAuth0Token String token) throws Exception {
        JWTClaimsSet decodedJWT = decode(token);

        long claim = decodedJWT.getDateClaim("exp").getTime(); // in seconds

        assertThat(claim).isLessThan(System.currentTimeMillis());
    }

    @Test
    public void testTokenIsNotYetIssued(@NotYetIssuedPartnerAuth0Token String token) throws Exception {
        JWTClaimsSet decodedJWT = decode(token);

        long claim = decodedJWT.getDateClaim("iat").getTime(); // in seconds

        assertThat(claim).isGreaterThan(System.currentTimeMillis() + Integer.MAX_VALUE / 2);
    }

    @Test
    public void testTokenSignatureInvalid(@InvalidSignaturePartnerAuth0Token String token) throws Exception {
        assertThat(token).endsWith("SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c");
    }

    @Test
    public void testTokenUnknownIssuer(@UnknownIssuerPartnerAuth0Token String token) throws Exception {
        JWTClaimsSet decodedJWT = decode(token);

        String claim = decodedJWT.getStringClaim("iss");

        assertThat(claim).isEqualTo("https://unknown.issuer");
    }

    @Test
    public void testTokenNullIssuer(@PartnerAuth0Token(organisationId = 5) @MissingClaim("iss") String token) throws Exception {
        JWTClaimsSet decodedJWT = decode(token);

        String claim = decodedJWT.getStringClaim("iss");

        assertThat(claim).isNull();
    }

    @Test
    public void testTokenUnknownAudience(@UnknownAudiencePartnerAuth0Token String token) throws Exception {
        JWTClaimsSet decodedJWT = decode(token);

        String[] claim = decodedJWT.getStringArrayClaim("aud");

        assertThat(claim[0]).isEqualTo("https://unknown.audience");
    }

    @Test
    public void testTokenUnknownKeyId(@UnknownKeyIdPartnerAuth0Token String token) throws Exception {
        Header header = decodeHeader(token);

        assertThat(header.toJSONObject().get("kid")).isEqualTo("unknown-kid");
    }

    private JWTClaimsSet decode(String token) throws ParseException {
        //return JWT.decode(token.substring(7));

        JWT jwt = JWTParser.parse(token.substring(7));

        return jwt.getJWTClaimsSet();
    }

    private Header decodeHeader(String token) throws ParseException {
        //return JWT.decode(token.substring(7));

        JWT jwt = JWTParser.parse(token.substring(7));

        return jwt.getHeader();
    }

}
