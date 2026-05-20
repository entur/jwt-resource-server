package org.entur.jwt.spring;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.source.CachingJWKSetSource;
import com.nimbusds.jose.jwk.source.RefreshAheadCachingJWKSetSource;
import com.nimbusds.jose.util.Base64URL;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class JwtKidIssuerCacheTest {

    private static final String ISSUER_1 = "https://issuer-1.example";
    private static final String ISSUER_2 = "https://issuer-2.example";
    private static final String ISSUER_3 = "https://issuer-3.example";

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
    void shouldActivateCacheOnceAllIssuersHaveReported() {
        JwtKidIssuerCache cache = new JwtKidIssuerCache(Set.of(ISSUER_1, ISSUER_2));

        sendRefreshEvent(cache, ISSUER_1, jwkSet("kid-1"));
        sendRefreshEvent(cache, ISSUER_2, jwkSet("kid-2"));

        assertThat(cache.lookupIssuer("kid-1")).isEqualTo(ISSUER_1);
        assertThat(cache.lookupIssuer("kid-2")).isEqualTo(ISSUER_2);
    }

    @Test
    void shouldExcludeOnlyConflictingKidWhenTwoIssuersShareIt() {
        JwtKidIssuerCache cache = new JwtKidIssuerCache(Set.of(ISSUER_1, ISSUER_2));

        sendRefreshEvent(cache, ISSUER_1, jwkSet("shared-kid"));
        sendRefreshEvent(cache, ISSUER_2, jwkSet("shared-kid"));

        // The shared kid is excluded (returns null → fall back to claim parsing).
        assertThat(cache.lookupIssuer("shared-kid")).isNull();
    }

    @Test
    void shouldKeepUniqueKidsWhenOnlyOneKidIsShared() {
        // ISSUER_1 has kid-1 (unique) and shared-kid
        // ISSUER_2 has kid-2 (unique) and shared-kid
        // Expected: kid-1 → ISSUER_1, kid-2 → ISSUER_2, shared-kid → null
        JwtKidIssuerCache cache = new JwtKidIssuerCache(Set.of(ISSUER_1, ISSUER_2));

        sendRefreshEvent(cache, ISSUER_1, jwkSet("kid-1", "shared-kid"));
        sendRefreshEvent(cache, ISSUER_2, jwkSet("kid-2", "shared-kid"));

        assertThat(cache.lookupIssuer("kid-1")).isEqualTo(ISSUER_1);
        assertThat(cache.lookupIssuer("kid-2")).isEqualTo(ISSUER_2);
        assertThat(cache.lookupIssuer("shared-kid")).isNull();
    }

    @Test
    void shouldUpdateCacheWhenJwkSetChanges() {
        JwtKidIssuerCache cache = new JwtKidIssuerCache(Set.of(ISSUER_1, ISSUER_2));

        sendRefreshEvent(cache, ISSUER_1, jwkSet("kid-1"));
        sendRefreshEvent(cache, ISSUER_2, jwkSet("kid-2"));
        assertThat(cache.lookupIssuer("kid-1")).isEqualTo(ISSUER_1);

        // Simulate key rotation for ISSUER_1.
        sendRefreshEvent(cache, ISSUER_1, jwkSet("kid-1-rotated"));
        assertThat(cache.lookupIssuer("kid-1")).isNull();
        assertThat(cache.lookupIssuer("kid-1-rotated")).isEqualTo(ISSUER_1);
    }

    @Test
    void shouldReEnableKidAfterRotationRemovesConflict() {
        JwtKidIssuerCache cache = new JwtKidIssuerCache(Set.of(ISSUER_1, ISSUER_2));

        sendRefreshEvent(cache, ISSUER_1, jwkSet("shared-kid"));
        sendRefreshEvent(cache, ISSUER_2, jwkSet("shared-kid"));
        assertThat(cache.lookupIssuer("shared-kid")).isNull();

        // ISSUER_2 rotates to a unique kid; conflict is resolved.
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

    @Test
    void shouldCacheThirdIssuerKidEvenIfTwoOtherIssuersShareADifferentKid() {
        JwtKidIssuerCache cache = new JwtKidIssuerCache(Set.of(ISSUER_1, ISSUER_2, ISSUER_3));

        sendRefreshEvent(cache, ISSUER_1, jwkSet("shared-kid"));
        sendRefreshEvent(cache, ISSUER_2, jwkSet("shared-kid"));
        sendRefreshEvent(cache, ISSUER_3, jwkSet("kid-3"));

        // ISSUER_1 and ISSUER_2 share a kid so that kid is excluded.
        assertThat(cache.lookupIssuer("shared-kid")).isNull();
        // ISSUER_3's unique kid remains in the cache.
        assertThat(cache.lookupIssuer("kid-3")).isEqualTo(ISSUER_3);
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

    private static JWKSet jwkSet(String... kids) {
        List<JWK> keys = new java.util.ArrayList<>();
        for (String kid : kids) {
            keys.add(new OctetSequenceKey.Builder(new Base64URL("AQIDBAUGBwgJCgsMDQ4PEA")).keyID(kid).build());
        }
        return new JWKSet(keys);
    }
}
