package org.entur.jwt.junit5.configuration.resolve;

import com.nimbusds.jwt.JWTParser;
import org.entur.jwt.junit5.AccessToken;
import org.entur.jwt.junit5.AuthorizationServer;
import org.entur.jwt.junit5.claim.Issuer;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.text.ParseException;
import java.util.Properties;

import static com.google.common.truth.Truth.assertThat;

/**
 * Issuer resolved from the properties file written by the PropertiesFileResourceServerConfigurationEnricher,
 * both registered via ServiceLoader.
 */

public class PropertiesFileAuthorizationServerConfigurationResolverTest {

    @Nested
    @AuthorizationServer
    class AuthorizationServerWithoutIdTest {

        @Test
        public void testIssuer(@AccessToken String token) throws Exception {
            String issuer = getProperty("entur.jwt.tenants.mock.issuer");
            assertThat(issuer).isNotNull();

            assertThat(getIssuer(token)).isEqualTo(issuer);
        }

        @Test
        public void testIssuerAnnotation(@AccessToken @Issuer("https://my.issuer") String token) throws Exception {
            assertThat(getIssuer(token)).isEqualTo("https://my.issuer");
        }
    }

    @Nested
    @AuthorizationServer("myKeycloak")
    @AuthorizationServer("myAuth0")
    class MultiTenantTest {

        @Test
        public void testIssuer(@AccessToken(by = "myAuth0") String token) throws Exception {
            String issuer = getProperty("entur.jwt.tenants.myAuth0.issuer");
            assertThat(issuer).isNotNull();
            assertThat(issuer).isNotEqualTo(getProperty("entur.jwt.tenants.myKeycloak.issuer"));

            assertThat(getIssuer(token)).isEqualTo(issuer);
        }
    }

    private static String getProperty(String name) throws IOException {
        Properties properties = new Properties();
        try (InputStream in = Files.newInputStream(Paths.get("target", "jwt.junit5.properties"))) {
            properties.load(in);
        }
        return properties.getProperty(name);
    }

    private static String getIssuer(String token) throws ParseException {
        return JWTParser.parse(token.substring(7)).getJWTClaimsSet().getIssuer();
    }
}
