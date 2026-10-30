package org.entur.jwt.spring.test;

import org.entur.jwt.junit5.AccessToken;
import org.entur.jwt.junit5.AuthorizationServer;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.test.context.junit.jupiter.SpringJUnitConfig;

import static com.google.common.truth.Truth.assertThat;
import static org.entur.jwt.spring.test.PerClassAccessTokenSpringTest.getIssuer;

/**
 * Token resolved for a {@literal @}BeforeAll method, i.e. before beforeEach.
 */

@AuthorizationServer
@SpringJUnitConfig(BeforeAllAccessTokenSpringTest.Config.class)
public class BeforeAllAccessTokenSpringTest {

    @Configuration
    static class Config {
    }

    private static String beforeAllToken;

    @Autowired
    private Environment environment;

    @BeforeAll
    public static void beforeAll(@AccessToken String token) {
        beforeAllToken = token;
    }

    @Test
    public void testIssuer(@AccessToken String token) {
        String issuer = environment.getProperty("entur.jwt.tenants.mock.issuer");
        assertThat(issuer).isNotNull();

        assertThat(getIssuer(token)).isEqualTo(issuer);
        assertThat(getIssuer(beforeAllToken)).isEqualTo(issuer);
    }
}
