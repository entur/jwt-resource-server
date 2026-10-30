package org.entur.jwt.spring.decode.cache;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import org.entur.jwt.spring.properties.JwtProperties;
import org.entur.jwt.spring.properties.jwk.JwtDecoderCacheProperties;
import org.entur.jwt.spring.properties.jwk.JwtTenantProperties;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

public class DecodedJwtCacheConfigurationReaderTest {

    private ListAppender<ILoggingEvent> logAppender;

    @BeforeEach
    public void setUpLogCapture() {
        logAppender = new ListAppender<>();
        logAppender.start();
        loggerUnderTest().addAppender(logAppender);
    }

    @AfterEach
    public void tearDownLogCapture() {
        loggerUnderTest().detachAppender(logAppender);
    }

    private static Logger loggerUnderTest() {
        return (Logger) LoggerFactory.getLogger(DecodedJwtCacheConfigurationReader.class);
    }

    @Test
    public void testIncludesOnlyEnabledTenantsWithEnabledDecoderCache() {
        JwtProperties jwt = jwtProperties();

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

    @Test
    public void testNoPreemptiveJwkRefreshRequired() {
        JwtProperties jwt = jwtProperties();
        jwt.getJwk().getCache().getPreemptive().setEnabled(false);
        jwt.getJwk().getCache().getPreemptive().getEager().setEnabled(false);

        jwt.getTenants().put("a", tenant("https://issuer-a", true, true));

        Map<String, JwtDecoderCacheProperties> result = DecodedJwtCacheConfigurationReader.getActiveJwtDecoderCacheProperties(jwt);

        assertThat(result).containsOnlyKeys("https://issuer-a");
        assertThat(logAppender.list).isEmpty();
    }

    @Test
    public void testFailsWhenDecoderCacheEnabledButJwkCacheDisabled() {
        JwtProperties jwt = jwtProperties();
        jwt.getJwk().getCache().setEnabled(false);

        jwt.getTenants().put("a", tenant("https://issuer-a", true, true));
        jwt.getTenants().put("b", tenant("https://issuer-b", true, false));
        jwt.getTenants().put("c", tenant("https://issuer-c", false, true));
        JwtTenantProperties zero = tenant("https://issuer-d", true, true);
        zero.getDecoderCache().setSize(0);
        jwt.getTenants().put("d", zero);

        assertThatThrownBy(() -> DecodedJwtCacheConfigurationReader.getActiveJwtDecoderCacheProperties(jwt))
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("decoder-cache.enabled=true for tenant(s) [a] requires entur.jwt.jwk.cache.enabled=true");
    }

    @Test
    public void testDoesNotFailWhenDecoderCacheDisabledAndJwkCacheDisabled() {
        JwtProperties jwt = jwtProperties();
        jwt.getJwk().getCache().setEnabled(false);

        jwt.getTenants().put("a", tenant("https://issuer-a", true, false));

        assertThat(DecodedJwtCacheConfigurationReader.getActiveJwtDecoderCacheProperties(jwt)).isEmpty();
        assertThat(logAppender.list).isEmpty();
    }

    @Test
    public void testDoesNotFailWhenDecoderCacheSizeIsZeroAndJwkCacheDisabled() {
        // size 0 is like enabled=false
        JwtProperties jwt = jwtProperties();
        jwt.getJwk().getCache().setEnabled(false);

        JwtTenantProperties zero = tenant("https://issuer-a", true, true);
        zero.getDecoderCache().setSize(0);
        jwt.getTenants().put("a", zero);

        assertThat(DecodedJwtCacheConfigurationReader.getActiveJwtDecoderCacheProperties(jwt)).isEmpty();
        assertThat(logAppender.list).anyMatch(e -> e.getFormattedMessage().contains("'a' has decoder-cache.size=0"));
    }

    @Test
    public void testSizeZeroDisablesCache() {
        JwtProperties jwt = jwtProperties();

        JwtTenantProperties zero = tenant("https://issuer-a", true, true);
        zero.getDecoderCache().setSize(0);
        jwt.getTenants().put("a", zero);
        jwt.getTenants().put("b", tenant("https://issuer-b", true, true));

        Map<String, JwtDecoderCacheProperties> result = DecodedJwtCacheConfigurationReader.getActiveJwtDecoderCacheProperties(jwt);

        assertThat(result).containsOnlyKeys("https://issuer-b");
        assertThat(logAppender.list).anyMatch(e -> e.getFormattedMessage().contains("'a' has decoder-cache.size=0"));
    }

    @Test
    public void testGetTenantsWithDecoderCacheEnabled() {
        JwtProperties jwt = jwtProperties();
        jwt.getTenants().put("a", tenant("https://issuer-a", true, true));
        jwt.getTenants().put("b", tenant("https://issuer-b", true, false));
        jwt.getTenants().put("c", tenant("https://issuer-c", false, true));

        assertThat(DecodedJwtCacheConfigurationReader.getTenantsWithDecoderCacheEnabled(jwt)).containsExactly("a");
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
