package org.entur.jwt.junit5.entur.test;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import org.entur.jwt.junit5.entur.test.auth0.PartnerAuth0AuthorizationServer;
import org.entur.jwt.junit5.entur.test.auth0.PartnerAuth0Token;
import org.junit.jupiter.api.Test;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import static com.google.common.truth.Truth.assertThat;

/**
 * Authorization server via a composed annotation.
 */

@ComposedPartnerAccessTokenTest.MyPartnerAuth0IntegrationTest
public class ComposedPartnerAccessTokenTest {

    @Retention(RetentionPolicy.RUNTIME)
    @Target(ElementType.TYPE)
    @PartnerAuth0AuthorizationServer(namespace = "https://my.namespace/")
    @interface MyPartnerAuth0IntegrationTest {
    }

    @Test
    public void testTokenWithNamespacedOrganisation(@PartnerAuth0Token(organisationId = 5) String token) throws Exception {
        JWTClaimsSet claims = JWTParser.parse(token.substring(7)).getJWTClaimsSet();

        assertThat(claims.getIntegerClaim("https://my.namespace/organisationID")).isEqualTo(5);
        assertThat(claims.getClaim("organisationID")).isNull();
    }
}
