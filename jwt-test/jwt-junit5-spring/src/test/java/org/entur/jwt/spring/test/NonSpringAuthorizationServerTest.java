package org.entur.jwt.spring.test;

import org.entur.jwt.junit5.AccessToken;
import org.entur.jwt.junit5.AuthorizationServer;
import org.entur.jwt.junit5.extension.AuthorizationServerExtension;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

import java.util.Base64;

import static com.google.common.truth.Truth.assertThat;

/**
 * Plain (non-Spring) unit test, with the Spring support on the classpath.
 */

@AuthorizationServer
public class NonSpringAuthorizationServerTest {

    @Test
    public void testAccessToken(@AccessToken String token) throws Exception {
        String payload = token.substring(7).split("\\.")[1];

        JsonNode claims = JsonMapper.builder().build().readTree(Base64.getUrlDecoder().decode(payload));

        assertThat(claims.get("iss").asString()).isEqualTo(AuthorizationServerExtension.toDefaultIssuer(""));
    }
}
