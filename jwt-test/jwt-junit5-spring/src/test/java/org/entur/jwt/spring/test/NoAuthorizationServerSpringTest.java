package org.entur.jwt.spring.test;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit.jupiter.SpringJUnitConfig;

import static com.google.common.truth.Truth.assertThat;

/**
 * Spring test without {@literal @}AuthorizationServer, with the Spring support on the classpath.
 */

@SpringJUnitConfig(NoAuthorizationServerSpringTest.Config.class)
@TestPropertySource(properties = "entur.jwt.tenants.myTenant.issuer=https://my.issuer.xyz")
public class NoAuthorizationServerSpringTest {

    @Configuration
    static class Config {
    }

    @Autowired
    private ConfigurableEnvironment environment;

    @Test
    public void testConfiguredTenantsAreNotDisabled() {
        assertThat(environment.getProperty("entur.jwt.tenants.myTenant.enabled")).isNull();
        assertThat(environment.getProperty("entur.jwt.tenants.myTenant.issuer")).isEqualTo("https://my.issuer.xyz");
        assertThat(environment.getPropertySources().contains(JwtTestContextCustomizerFactory.PROPERTY_SOURCE_NAME)).isFalse();
    }
}
