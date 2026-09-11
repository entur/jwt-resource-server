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
    public void testWarnsWhenOutageCacheDurationsMismatch() {
        JwtProperties jwt = jwtProperties();
        jwt.getJwk().getCache().setEnabled(true);
        jwt.getJwk().getCache().getPreemptive().setEnabled(true);
        jwt.getJwk().getCache().getPreemptive().getEager().setEnabled(true);
        jwt.getJwk().getOutageCache().setEnabled(true);
        jwt.getJwk().getOutageCache().setTimeToLive(3600L);

        JwtTenantProperties tenant = tenant("https://issuer-a", true, true);
        tenant.getDecoderCache().getOutageCache().setEnabled(true);
        tenant.getDecoderCache().getOutageCache().setTimeToLive(7200L);
        jwt.getTenants().put("a", tenant);

        DecodedJwtCacheConfigurationReader.getActiveJwtDecoderCacheProperties(jwt);

        List<ILoggingEvent> warnings = logAppender.list;
        assertThat(warnings).hasSize(1);
        assertThat(warnings.get(0).getFormattedMessage()).contains("a", "3600", "7200");
    }

    @Test
    public void testDoesNotWarnWhenOutageCacheDurationsMatch() {
        JwtProperties jwt = jwtProperties();
        jwt.getJwk().getCache().setEnabled(true);
        jwt.getJwk().getCache().getPreemptive().setEnabled(true);
        jwt.getJwk().getCache().getPreemptive().getEager().setEnabled(true);
        jwt.getJwk().getOutageCache().setEnabled(true);
        jwt.getJwk().getOutageCache().setTimeToLive(3600L);

        JwtTenantProperties tenant = tenant("https://issuer-a", true, true);
        tenant.getDecoderCache().getOutageCache().setEnabled(true);
        tenant.getDecoderCache().getOutageCache().setTimeToLive(3600L);
        jwt.getTenants().put("a", tenant);

        DecodedJwtCacheConfigurationReader.getActiveJwtDecoderCacheProperties(jwt);

        assertThat(logAppender.list).isEmpty();
    }

    @Test
    public void testDoesNotWarnWhenOneOutageCacheIsDisabled() {
        JwtProperties jwt = jwtProperties();
        jwt.getJwk().getCache().setEnabled(true);
        jwt.getJwk().getCache().getPreemptive().setEnabled(true);
        jwt.getJwk().getCache().getPreemptive().getEager().setEnabled(true);
        jwt.getJwk().getOutageCache().setEnabled(false);
        jwt.getJwk().getOutageCache().setTimeToLive(3600L);

        JwtTenantProperties tenant = tenant("https://issuer-a", true, true);
        tenant.getDecoderCache().getOutageCache().setEnabled(true);
        tenant.getDecoderCache().getOutageCache().setTimeToLive(7200L);
        jwt.getTenants().put("a", tenant);

        DecodedJwtCacheConfigurationReader.getActiveJwtDecoderCacheProperties(jwt);

        assertThat(logAppender.list).isEmpty();
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
