package org.entur.jwt.spring;

import org.entur.jwt.spring.properties.jwk.JwtTenantProperties;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class JwtTenantIssuersTest {

    @Test
    void testUniqueIssuers() {
        Map<String, JwtTenantProperties> tenants = new HashMap<>();
        tenants.put("a", tenant("https://issuer.a", true));
        tenants.put("b", tenant("https://issuer.b", true));

        assertThatCode(() -> JwtTenantIssuers.requireUniqueIssuers(tenants)).doesNotThrowAnyException();
    }

    @Test
    void testFailsOnDuplicateIssuer() {
        Map<String, JwtTenantProperties> tenants = new HashMap<>();
        tenants.put("b", tenant("https://issuer.a", true));
        tenants.put("a", tenant("https://issuer.a", true));
        tenants.put("c", tenant("https://issuer.c", true));

        assertThatThrownBy(() -> JwtTenantIssuers.requireUniqueIssuers(tenants))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageStartingWith("Tenants 'a' and 'b' have the same issuer 'https://issuer.a'.");
    }

    @Test
    void testIgnoresDisabledTenants() {
        Map<String, JwtTenantProperties> tenants = new HashMap<>();
        tenants.put("a", tenant("https://issuer.a", true));
        tenants.put("b", tenant("https://issuer.a", false));

        assertThatCode(() -> JwtTenantIssuers.requireUniqueIssuers(tenants)).doesNotThrowAnyException();
    }

    private static JwtTenantProperties tenant(String issuer, boolean enabled) {
        JwtTenantProperties tenant = new JwtTenantProperties();
        tenant.setIssuer(issuer);
        tenant.setEnabled(enabled);
        return tenant;
    }
}
