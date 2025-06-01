package org.entur.jwt.junit5;

import static org.junit.Assert.assertNotNull;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Properties;

import org.entur.jwt.junit5.claim.IntegerClaim;
import org.entur.jwt.junit5.claim.Subject;

@AuthorizationServer("partner-auth0")
public class AuthorizationServerTest {

    @org.junit.jupiter.api.Test
    public void test(@AccessToken @IntegerClaim(name = "https://entur.io/organisationID", value = 1) @Subject("user1") String token) throws IOException {

        Path path = Paths.get("target", "jwt.junit5.properties");

        Properties properties = new Properties();
        properties.load(Files.newInputStream(path));

        assertNotNull(properties.get("entur.jwt.tenants.partner-auth0.jwk.location"));
    }
}
