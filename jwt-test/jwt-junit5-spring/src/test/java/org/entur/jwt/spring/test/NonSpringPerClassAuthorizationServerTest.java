package org.entur.jwt.spring.test;

import org.entur.jwt.junit5.AccessToken;
import org.entur.jwt.junit5.AuthorizationServer;
import org.entur.jwt.junit5.extention.AuthorizationServerExtension;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

import static com.google.common.truth.Truth.assertThat;
import static org.entur.jwt.spring.test.PerClassAccessTokenSpringTest.getIssuer;

/**
 * Plain (non-Spring) unit test with a per-class test instance lifecycle, with the Spring support on the classpath.
 */

@AuthorizationServer
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class NonSpringPerClassAuthorizationServerTest {

    private final String constructorToken;

    public NonSpringPerClassAuthorizationServerTest(@AccessToken String token) {
        this.constructorToken = token;
    }

    @Test
    public void testAccessToken() {
        assertThat(getIssuer(constructorToken)).isEqualTo(AuthorizationServerExtension.toDefaultIssuer(""));
    }
}
