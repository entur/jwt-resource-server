package org.entur.jwt.spring;

import org.entur.jwt.spring.properties.jwk.JwtTenantProperties;

import java.util.HashMap;
import java.util.Map;
import java.util.TreeMap;

/**
 * JWTs are mapped to tenants by issuer, so each enabled tenant must have a unique issuer.
 */
public class JwtTenantIssuers {

    private JwtTenantIssuers() {
    }

    /**
     * Fail if two enabled tenants have the same issuer, as only one of them could be used.
     *
     * @param tenants tenants by tenant id
     */
    public static void requireUniqueIssuers(Map<String, JwtTenantProperties> tenants) {
        Map<String, String> issuerTenants = new HashMap<>();
        // sort by tenant id, for a predictable error message
        for (Map.Entry<String, JwtTenantProperties> entry : new TreeMap<>(tenants).entrySet()) {
            JwtTenantProperties tenant = entry.getValue();
            if (!tenant.isEnabled()) {
                continue;
            }
            String otherTenant = issuerTenants.putIfAbsent(tenant.getIssuer(), entry.getKey());
            if (otherTenant != null) {
                throw new IllegalStateException("Tenants '" + otherTenant + "' and '" + entry.getKey() + "' have the same issuer '" + tenant.getIssuer() + "'. "
                        + "The issuer of each enabled tenant must be unique: remove one of the tenants, or disable it using entur.jwt.tenants.<tenant>.enabled=false.");
            }
        }
    }
}
