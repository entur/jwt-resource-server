package org.entur.jwt.junit5.entur.test;

import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.entur.jwt.junit5.entur.test.auth0.PartnerAuth0AuthorizationServer;
import org.entur.jwt.junit5.entur.test.auth0.PartnerAuth0Token;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Properties;

import static com.google.common.truth.Truth.assertThat;

@PartnerAuth0AuthorizationServer
public class NestedPartnerAccessTokenTest {

    @Test
    public void testTokenIsSignedByPublishedKey(@PartnerAuth0Token(organisationId = 5) String token) throws Exception {
        JWTClaimsSet claims = verify(token);

        assertThat(claims.getIntegerClaim("https://entur.io/organisationID")).isEqualTo(5);
    }

    @Nested
    @PartnerAuth0AuthorizationServer(namespace = "https://other/")
    class OverridingAuthorizationServerTest {

        @Test
        public void testTokenIsSignedByPublishedKey(@PartnerAuth0Token(organisationId = 5) String token) throws Exception {
            JWTClaimsSet claims = verify(token);

            assertThat(claims.getIntegerClaim("https://other/organisationID")).isEqualTo(5);
        }
    }

    private static JWTClaimsSet verify(String token) throws Exception {
        // keys as published to the resource server
        Properties properties = new Properties();
        try (InputStream in = Files.newInputStream(Paths.get("target", "jwt.junit5.properties"))) {
            properties.load(in);
        }
        String location = properties.getProperty("entur.jwt.tenants.partner-auth0.jwk.location");
        JWKSet jwkSet = JWKSet.parse(Files.readString(Paths.get(URI.create(location))));

        SignedJWT jwt = SignedJWT.parse(token.substring(7));

        RSAKey key = (RSAKey) jwkSet.getKeyByKeyId(jwt.getHeader().getKeyID());
        assertThat(key).isNotNull();
        assertThat(jwt.verify(new RSASSAVerifier(key))).isTrue();

        return jwt.getJWTClaimsSet();
    }
}
