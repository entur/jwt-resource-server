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

    @Test
    public void testWarnsWhenDecoderCacheEnabledButEagerRefreshDisabled() {
        JwtProperties jwt = jwtProperties();
        jwt.getJwk().getCache().setEnabled(true);
        jwt.getJwk().getCache().getPreemptive().setEnabled(true);
        jwt.getJwk().getCache().getPreemptive().getEager().setEnabled(false);

        jwt.getTenants().put("a", tenant("https://issuer-a", true, true));
        jwt.getTenants().put("b", tenant("https://issuer-b", true, false));
        jwt.getTenants().put("c", tenant("https://issuer-c", false, true));

        Map<String, JwtDecoderCacheProperties> result = DecodedJwtCacheConfigurationReader.getActiveJwtDecoderCacheProperties(jwt);

        assertThat(result).isEmpty();
        List<ILoggingEvent> warnings = logAppender.list;
        assertThat(warnings).hasSize(1);
        assertThat(warnings.get(0).getFormattedMessage()).contains("'a'", "eager");
    }

    @Test
    public void testDoesNotWarnWhenDecoderCacheDisabledAndEagerRefreshDisabled() {
        JwtProperties jwt = jwtProperties();
        jwt.getJwk().getCache().getPreemptive().getEager().setEnabled(false);

        jwt.getTenants().put("a", tenant("https://issuer-a", true, false));

        DecodedJwtCacheConfigurationReader.getActiveJwtDecoderCacheProperties(jwt);

        assertThat(logAppender.list).isEmpty();
    }

    @Test
    public void testSizeZeroDisablesCache() {
        JwtProperties jwt = jwtProperties();
        jwt.getJwk().getCache().setEnabled(true);
        jwt.getJwk().getCache().getPreemptive().setEnabled(true);
        jwt.getJwk().getCache().getPreemptive().getEager().setEnabled(true);

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
