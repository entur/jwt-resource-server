package org.entur.jwt.spring.test;

import org.entur.jwt.junit5.AccessToken;
import org.entur.jwt.junit5.AuthorizationServer;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.test.context.junit.jupiter.SpringJUnitConfig;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

import java.util.Base64;

import static com.google.common.truth.Truth.assertThat;

/**
 * Tokens resolved for the constructor (i.e. before beforeAll) and {@literal @}BeforeAll method with a per-class test instance lifecycle.
 */

@AuthorizationServer
@SpringJUnitConfig(PerClassAccessTokenSpringTest.Config.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class PerClassAccessTokenSpringTest {

    @Configuration
    static class Config {
    }

    private final String constructorToken;

    private String beforeAllToken;

    @Autowired
    private Environment environment;

    public PerClassAccessTokenSpringTest(@AccessToken String token) {
        this.constructorToken = token;
    }

    @BeforeAll
    public void beforeAll(@AccessToken String token) {
        this.beforeAllToken = token;
    }

    @Test
    public void testIssuer(@AccessToken String token) {
        String issuer = environment.getProperty("entur.jwt.tenants.mock.issuer");
        assertThat(issuer).isNotNull();

        assertThat(getIssuer(token)).isEqualTo(issuer);
        assertThat(getIssuer(constructorToken)).isEqualTo(issuer);
        assertThat(getIssuer(beforeAllToken)).isEqualTo(issuer);
    }

    static String getIssuer(String token) {
        String payload = token.substring(7).split("\\.")[1];

        JsonNode claims = JsonMapper.builder().build().readTree(Base64.getUrlDecoder().decode(payload));

        return claims.get("iss").asString();
    }
}
