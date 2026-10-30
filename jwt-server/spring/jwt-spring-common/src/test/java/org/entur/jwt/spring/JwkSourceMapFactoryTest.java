package org.entur.jwt.spring;

import org.entur.jwt.spring.actuate.ListJwksHealthIndicator;
import org.entur.jwt.spring.properties.jwk.JwkLocationProperties;
import org.entur.jwt.spring.properties.jwk.JwkProperties;
import org.entur.jwt.spring.properties.jwk.JwtTenantProperties;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

class JwkSourceMapFactoryTest {

    @Test
    void testTenantsWithDifferentIssuers() throws Exception {
        Map<String, JwtTenantProperties> tenants = new HashMap<>();
        tenants.put("a", tenant("https://issuer.a", "http://localhost:1/a/jwks.json"));
        tenants.put("b", tenant("https://issuer.b", "http://localhost:1/b/jwks.json"));

        ListJwksHealthIndicator healthIndicator = mock(ListJwksHealthIndicator.class);

        try (JwkSourceMap<?> jwkSourceMap = new JwkSourceMapFactory<>().getJwkSourceMap(tenants, new JwkProperties(), healthIndicator)) {
            assertThat(jwkSourceMap.getJwkSources()).containsOnlyKeys("https://issuer.a", "https://issuer.b");
            assertThat(jwkSourceMap.getJwkEventListeners()).containsOnlyKeys("https://issuer.a", "https://issuer.b");
        }
        verify(healthIndicator, times(2)).addHealthIndicators(any());
    }

    @Test
    void testFailsOnDuplicateIssuerBeforeCreatingJwkSources() {
        // previously, one of the JWK sources was silently dropped (and never closed)
        Map<String, JwtTenantProperties> tenants = new HashMap<>();
        tenants.put("a", tenant("https://issuer", "http://localhost:1/a/jwks.json"));
        tenants.put("b", tenant("https://issuer", "http://localhost:1/b/jwks.json"));

        ListJwksHealthIndicator healthIndicator = mock(ListJwksHealthIndicator.class);

        assertThatThrownBy(() -> new JwkSourceMapFactory<>().getJwkSourceMap(tenants, new JwkProperties(), healthIndicator))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageStartingWith("Tenants 'a' and 'b' have the same issuer 'https://issuer'.");

        verifyNoInteractions(healthIndicator);
    }

    private static JwtTenantProperties tenant(String issuer, String location) {
        JwkLocationProperties jwk = new JwkLocationProperties();
        jwk.setLocation(location);

        JwtTenantProperties tenant = new JwtTenantProperties();
        tenant.setIssuer(issuer);
        tenant.setJwk(jwk);
        return tenant;
    }
}
