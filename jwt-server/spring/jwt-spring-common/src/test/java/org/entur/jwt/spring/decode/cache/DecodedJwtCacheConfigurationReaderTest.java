package org.entur.jwt.spring.decode.cache;

import org.entur.jwt.spring.properties.JwtProperties;
import org.entur.jwt.spring.properties.jwk.JwtDecoderCacheProperties;
import org.entur.jwt.spring.properties.jwk.JwtTenantProperties;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

public class DecodedJwtCacheConfigurationReaderTest {

    @Test
    public void testEmptyWhenJwkCacheDisabled() {
        JwtProperties jwt = jwtProperties();
        jwt.getJwk().getCache().setEnabled(false);

        JwtTenantProperties tenant = tenant("https://issuer-a", true, true);
        jwt.getTenants().put("a", tenant);

        Map<String, JwtDecoderCacheProperties> result = DecodedJwtCacheConfigurationReader.getActiveJwtDecoderCacheProperties(jwt);

        assertThat(result).isEmpty();
    }

    @Test
    public void testEmptyWhenPreemptiveDisabled() {
        JwtProperties jwt = jwtProperties();
        jwt.getJwk().getCache().setEnabled(true);
        jwt.getJwk().getCache().getPreemptive().setEnabled(false);

        JwtTenantProperties tenant = tenant("https://issuer-a", true, true);
        jwt.getTenants().put("a", tenant);

        Map<String, JwtDecoderCacheProperties> result = DecodedJwtCacheConfigurationReader.getActiveJwtDecoderCacheProperties(jwt);

        assertThat(result).isEmpty();
    }

    @Test
    public void testEmptyWhenEagerDisabled() {
        JwtProperties jwt = jwtProperties();
        jwt.getJwk().getCache().setEnabled(true);
        jwt.getJwk().getCache().getPreemptive().setEnabled(true);
        jwt.getJwk().getCache().getPreemptive().getEager().setEnabled(false);

        JwtTenantProperties tenant = tenant("https://issuer-a", true, true);
        jwt.getTenants().put("a", tenant);

        Map<String, JwtDecoderCacheProperties> result = DecodedJwtCacheConfigurationReader.getActiveJwtDecoderCacheProperties(jwt);

        assertThat(result).isEmpty();
    }

    @Test
    public void testIncludesOnlyEnabledTenantsWithEnabledDecoderCache() {
        JwtProperties jwt = jwtProperties();
        jwt.getJwk().getCache().setEnabled(true);
        jwt.getJwk().getCache().getPreemptive().setEnabled(true);
        jwt.getJwk().getCache().getPreemptive().getEager().setEnabled(true);

        JwtTenantProperties enabledWithCache = tenant("https://issuer-a", true, true);
        JwtTenantProperties enabledWithoutCache = tenant("https://issuer-b", true, false);
        JwtTenantProperties disabledTenant = tenant("https://issuer-c", false, true);

        jwt.getTenants().put("a", enabledWithCache);
        jwt.getTenants().put("b", enabledWithoutCache);
        jwt.getTenants().put("c", disabledTenant);

        Map<String, JwtDecoderCacheProperties> result = DecodedJwtCacheConfigurationReader.getActiveJwtDecoderCacheProperties(jwt);

        assertThat(result).hasSize(1);
        assertThat(result).containsKey("https://issuer-a");
        assertThat(result.get("https://issuer-a")).isSameAs(enabledWithCache.getDecoderCache());
    }

    private static JwtTenantProperties tenant(String issuer, boolean enabled, boolean decoderCacheEnabled) {
        JwtTenantProperties tenant = new JwtTenantProperties();
        tenant.setIssuer(issuer);
        tenant.setEnabled(enabled);
        tenant.getDecoderCache().setEnabled(decoderCacheEnabled);
        return tenant;
    }

    private static JwtProperties jwtProperties() {
        return new JwtProperties();
    }
}
