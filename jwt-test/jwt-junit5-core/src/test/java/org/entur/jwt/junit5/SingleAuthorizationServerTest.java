package org.entur.jwt.junit5;

import static org.junit.Assert.assertNotNull;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Properties;

import org.entur.jwt.junit5.AccessToken;
import org.entur.jwt.junit5.AuthorizationServer;
import org.junit.jupiter.api.Test;

@AuthorizationServer
public class SingleAuthorizationServerTest {

    @Test
    public void test(@AccessToken String token) throws IOException {
        Path path = Paths.get("jwt.junit5.properties");

        Properties properties = new Properties();
        properties.load(Files.newInputStream(path));

        assertNotNull(properties.get("entur.jwt.tenants.mock.jwk.location"));
    }
}
