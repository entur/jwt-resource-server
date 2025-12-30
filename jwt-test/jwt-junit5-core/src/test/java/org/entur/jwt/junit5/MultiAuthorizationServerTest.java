package org.entur.jwt.junit5;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Properties;

import static org.junit.Assert.assertNotNull;

@AuthorizationServer("myKeycloak")
@AuthorizationServer("myAuth0")
public class MultiAuthorizationServerTest {

    @Test
    public void test(@AccessToken(by = "myKeycloak") String token) throws IOException {
        Path path = Paths.get("target", "jwt.junit5.properties");

        Properties properties = new Properties();
        properties.load(Files.newInputStream(path));

        assertNotNull(properties.get("entur.jwt.tenants.myKeycloak.jwk.location"));
        assertNotNull(properties.get("entur.jwt.tenants.myAuth0.jwk.location"));
    }
}
