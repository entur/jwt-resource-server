package org.entur.jwt.spring;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.source.CachingJWKSetSource;
import com.nimbusds.jose.jwk.source.RefreshAheadCachingJWKSetSource;
import com.nimbusds.jose.util.Base64URL;
import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class JwtKidIssuerCacheTest {

    private static final String ISSUER_1 = "https://issuer-1.example";
    private static final String ISSUER_2 = "https://issuer-2.example";

    @Test
    void shouldReturnNullBeforeAnyJwkSetsAreLoaded() {
        JwtKidIssuerCache cache = new JwtKidIssuerCache(Set.of(ISSUER_1, ISSUER_2));

        assertThat(cache.lookupIssuer("kid-1")).isNull();
    }

    @Test
    void shouldReturnNullUntilAllIssuersHaveReported() {
        JwtKidIssuerCache cache = new JwtKidIssuerCache(Set.of(ISSUER_1, ISSUER_2));

        sendRefreshEvent(cache, ISSUER_1, jwkSet("kid-1"));

        assertThat(cache.lookupIssuer("kid-1")).isNull();
    }

    @Test
    void shouldActivateFastPathOnceAllIssuersHaveReported() {
        JwtKidIssuerCache cache = new JwtKidIssuerCache(Set.of(ISSUER_1, ISSUER_2));

        sendRefreshEvent(cache, ISSUER_1, jwkSet("kid-1"));
        sendRefreshEvent(cache, ISSUER_2, jwkSet("kid-2"));

        assertThat(cache.lookupIssuer("kid-1")).isEqualTo(ISSUER_1);
        assertThat(cache.lookupIssuer("kid-2")).isEqualTo(ISSUER_2);
    }

    @Test
    void shouldDisableFastPathWhenKidsAreSharedAcrossIssuers() {
        JwtKidIssuerCache cache = new JwtKidIssuerCache(Set.of(ISSUER_1, ISSUER_2));

        sendRefreshEvent(cache, ISSUER_1, jwkSet("shared-kid"));
        sendRefreshEvent(cache, ISSUER_2, jwkSet("shared-kid"));

        assertThat(cache.lookupIssuer("shared-kid")).isNull();
    }

    @Test
    void shouldUpdateCacheWhenJwkSetChanges() {
        JwtKidIssuerCache cache = new JwtKidIssuerCache(Set.of(ISSUER_1, ISSUER_2));

        sendRefreshEvent(cache, ISSUER_1, jwkSet("kid-1"));
        sendRefreshEvent(cache, ISSUER_2, jwkSet("kid-2"));
        assertThat(cache.lookupIssuer("kid-1")).isEqualTo(ISSUER_1);

        sendRefreshEvent(cache, ISSUER_1, jwkSet("kid-1-rotated"));
        assertThat(cache.lookupIssuer("kid-1")).isNull();
        assertThat(cache.lookupIssuer("kid-1-rotated")).isEqualTo(ISSUER_1);
    }

    @Test
    void shouldReactivateFastPathAfterRotationRemovesConflict() {
        JwtKidIssuerCache cache = new JwtKidIssuerCache(Set.of(ISSUER_1, ISSUER_2));

        sendRefreshEvent(cache, ISSUER_1, jwkSet("shared-kid"));
        sendRefreshEvent(cache, ISSUER_2, jwkSet("shared-kid"));
        assertThat(cache.lookupIssuer("shared-kid")).isNull();

        sendRefreshEvent(cache, ISSUER_2, jwkSet("kid-2-unique"));
        assertThat(cache.lookupIssuer("shared-kid")).isEqualTo(ISSUER_1);
        assertThat(cache.lookupIssuer("kid-2-unique")).isEqualTo(ISSUER_2);
    }

    @Test
    void shouldHandleScheduledRefreshCompletedEvent() {
        JwtKidIssuerCache cache = new JwtKidIssuerCache(Set.of(ISSUER_1));

        sendScheduledRefreshEvent(cache, ISSUER_1, jwkSet("kid-1"));

        assertThat(cache.lookupIssuer("kid-1")).isEqualTo(ISSUER_1);
    }

    // ---- helpers -----------------------------------------------------------

    @SuppressWarnings("unchecked")
    private static void sendRefreshEvent(JwtKidIssuerCache cache, String issuer, JWKSet jwkSet) {
        CachingJWKSetSource.RefreshCompletedEvent<?> event =
                mock(CachingJWKSetSource.RefreshCompletedEvent.class);
        when(event.getJWKSet()).thenReturn(jwkSet);
        cache.listenerFor(issuer).notify(event);
    }

    @SuppressWarnings("unchecked")
    private static void sendScheduledRefreshEvent(JwtKidIssuerCache cache, String issuer, JWKSet jwkSet) {
        RefreshAheadCachingJWKSetSource.ScheduledRefreshCompletedEvent<?> event =
                mock(RefreshAheadCachingJWKSetSource.ScheduledRefreshCompletedEvent.class);
        when(event.getJWKSet()).thenReturn(jwkSet);
        cache.listenerFor(issuer).notify(event);
    }

    private static JWKSet jwkSet(String kid) {
        JWK key = new OctetSequenceKey.Builder(new Base64URL("AQIDBAUGBwgJCgsMDQ4PEA")).keyID(kid).build();
        return new JWKSet(key);
    }
}
