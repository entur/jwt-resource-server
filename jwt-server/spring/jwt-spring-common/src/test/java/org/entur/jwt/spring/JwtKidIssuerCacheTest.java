package org.entur.jwt.spring;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.source.CachingJWKSetSource;
import com.nimbusds.jose.jwk.source.RefreshAheadCachingJWKSetSource;
import com.nimbusds.jose.util.Base64URL;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
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
    void shouldDisableBothIssuersWhenTheyShareAKid() {
        JwtKidIssuerCache cache = new JwtKidIssuerCache(Set.of(ISSUER_1, ISSUER_2));

        sendRefreshEvent(cache, ISSUER_1, jwkSet("shared-kid"));
        sendRefreshEvent(cache, ISSUER_2, jwkSet("shared-kid"));

        // Both issuers are disabled; no kid from either appears in the cache.
        assertThat(cache.lookupIssuer("shared-kid")).isNull();
    }

    @Test
    void shouldDisableAllKidsOfBothIssuersWhenTheyShareAnyKid() {
        // ISSUER_1 has kid-1 (unique) and shared-kid
        // ISSUER_2 has kid-2 (unique) and shared-kid
        // Both issuers are fully disabled because they share at least one kid.
        JwtKidIssuerCache cache = new JwtKidIssuerCache(Set.of(ISSUER_1, ISSUER_2));

        sendRefreshEvent(cache, ISSUER_1, jwkSet("kid-1", "shared-kid"));
        sendRefreshEvent(cache, ISSUER_2, jwkSet("kid-2", "shared-kid"));

        assertThat(cache.lookupIssuer("kid-1")).isNull();
        assertThat(cache.lookupIssuer("kid-2")).isNull();
        assertThat(cache.lookupIssuer("shared-kid")).isNull();
    }

    @Test
    void shouldKeepThirdIssuerCachedWhenTwoOtherIssuersShareAKid() {
        JwtKidIssuerCache cache = new JwtKidIssuerCache(Set.of(ISSUER_1, ISSUER_2, ISSUER_3));

        sendRefreshEvent(cache, ISSUER_1, jwkSet("shared-kid"));
        sendRefreshEvent(cache, ISSUER_2, jwkSet("shared-kid"));
        sendRefreshEvent(cache, ISSUER_3, jwkSet("kid-3"));

        // ISSUER_1 and ISSUER_2 are disabled; ISSUER_3 remains cached.
        assertThat(cache.lookupIssuer("shared-kid")).isNull();
        assertThat(cache.lookupIssuer("kid-3")).isEqualTo(ISSUER_3);
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
    void shouldReEnableIssuersAfterRotationRemovesConflict() {
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
    void shouldSkipRecomputeWhenKidsAreUnchanged() {
        JwtKidIssuerCache cache = new JwtKidIssuerCache(Set.of(ISSUER_1, ISSUER_2));

        sendRefreshEvent(cache, ISSUER_1, jwkSet("kid-1"));
        sendRefreshEvent(cache, ISSUER_2, jwkSet("kid-2"));
        assertThat(cache.lookupIssuer("kid-1")).isEqualTo(ISSUER_1);

        // Send same JWK set (same kid) again — cache should remain consistent.
        sendRefreshEvent(cache, ISSUER_1, jwkSet("kid-1"));
        assertThat(cache.lookupIssuer("kid-1")).isEqualTo(ISSUER_1);
        assertThat(cache.lookupIssuer("kid-2")).isEqualTo(ISSUER_2);
    }

    @Test
    void shouldHandleScheduledRefreshCompletedEvent() {
        JwtKidIssuerCache cache = new JwtKidIssuerCache(Set.of(ISSUER_1));

        sendScheduledRefreshEvent(cache, ISSUER_1, jwkSet("kid-1"));

        assertThat(cache.lookupIssuer("kid-1")).isEqualTo(ISSUER_1);
    }

    @Test
    void shouldLookupIssuerByRawHeaderOnFirstCall() {
        JwtKidIssuerCache cache = new JwtKidIssuerCache(Set.of(ISSUER_1, ISSUER_2));
        sendRefreshEvent(cache, ISSUER_1, jwkSet("kid-1"));
        sendRefreshEvent(cache, ISSUER_2, jwkSet("kid-2"));

        String rawHeader = rawHeaderForKid("kid-1");
        assertThat(cache.lookupIssuerByRawHeader(rawHeader)).isEqualTo(ISSUER_1);
    }

    @Test
    void shouldCacheRawHeaderOnFirstLookupAndReturnDirectlyOnSubsequentCall() {
        JwtKidIssuerCache cache = new JwtKidIssuerCache(Set.of(ISSUER_1, ISSUER_2));
        sendRefreshEvent(cache, ISSUER_1, jwkSet("kid-1"));
        sendRefreshEvent(cache, ISSUER_2, jwkSet("kid-2"));

        String rawHeader = rawHeaderForKid("kid-1");
        // First call: tier-2 (kid extraction)
        assertThat(cache.lookupIssuerByRawHeader(rawHeader)).isEqualTo(ISSUER_1);
        // Second call: tier-1 (raw header cache hit, no parsing)
        assertThat(cache.lookupIssuerByRawHeader(rawHeader)).isEqualTo(ISSUER_1);
    }

    @Test
    void shouldClearRawHeaderCacheOnKeyRotation() {
        JwtKidIssuerCache cache = new JwtKidIssuerCache(Set.of(ISSUER_1, ISSUER_2));
        sendRefreshEvent(cache, ISSUER_1, jwkSet("kid-1"));
        sendRefreshEvent(cache, ISSUER_2, jwkSet("kid-2"));

        String rawHeader = rawHeaderForKid("kid-1");
        assertThat(cache.lookupIssuerByRawHeader(rawHeader)).isEqualTo(ISSUER_1);

        // Rotate kid for ISSUER_1; raw header cache must be cleared.
        sendRefreshEvent(cache, ISSUER_1, jwkSet("kid-1-rotated"));

        // Old raw header no longer resolves.
        assertThat(cache.lookupIssuerByRawHeader(rawHeader)).isNull();
        // New kid resolves (via tier-2 since tier-1 was cleared).
        assertThat(cache.lookupIssuerByRawHeader(rawHeaderForKid("kid-1-rotated"))).isEqualTo(ISSUER_1);
    }

    @Test
    void shouldReturnNullFromRawHeaderLookupWhenHeaderHasNoKid() {
        JwtKidIssuerCache cache = new JwtKidIssuerCache(Set.of(ISSUER_1));
        sendRefreshEvent(cache, ISSUER_1, jwkSet("kid-1"));

        // Header with no kid field.
        String rawHeaderNoKid = Base64.getUrlEncoder().withoutPadding()
                .encodeToString("{\"alg\":\"RS256\"}".getBytes(StandardCharsets.UTF_8));
        assertThat(cache.lookupIssuerByRawHeader(rawHeaderNoKid)).isNull();
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
        List<JWK> keys = new ArrayList<>();
        for (String kid : kids) {
            keys.add(new OctetSequenceKey.Builder(new Base64URL("AQIDBAUGBwgJCgsMDQ4PEA")).keyID(kid).build());
        }
        return new JWKSet(keys);
    }

    /** Returns the raw base64url-encoded JWS header string for {@code {"alg":"RS256","kid":"<kid>"}}.*/
    private static String rawHeaderForKid(String kid) {
        String json = "{\"alg\":\"RS256\",\"kid\":\"" + kid + "\"}";
        return Base64.getUrlEncoder().withoutPadding().encodeToString(json.getBytes(StandardCharsets.UTF_8));
    }
}
