package org.entur.jwt.spring;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.source.CachingJWKSetSource;
import com.nimbusds.jose.jwk.source.RefreshAheadCachingJWKSetSource;
import com.nimbusds.jose.util.Base64URL;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class JwtKidIssuerCacheTest {

    private static final String ISSUER_1 = "https://issuer-1.example";
    private static final String ISSUER_2 = "https://issuer-2.example";
    private static final String ISSUER_3 = "https://issuer-3.example";

    @Test
    void shouldReturnNullBeforeAnyJwkSetsAreLoaded() {
        JwtKidIssuerCacheFactory factory = new JwtKidIssuerCacheFactory();
        factory.createContext(ISSUER_1);
        factory.createContext(ISSUER_2);

        assertThat(factory.getCache().lookupIssuer(tokenForKid("kid-1"))).isNull();
    }

    @Test
    void shouldReturnNullUntilAllIssuersHaveReported() {
        JwtKidIssuerCacheFactory factory = new JwtKidIssuerCacheFactory();
        factory.createContext(ISSUER_2); // pre-register so factory knows it hasn't loaded yet

        sendRefreshEvent(factory, ISSUER_1, jwkSet("kid-1"));

        assertThat(factory.getCache().lookupIssuer(tokenForKid("kid-1"))).isNull();
    }

    @Test
    void shouldActivateCacheOnceAllIssuersHaveReported() {
        JwtKidIssuerCacheFactory factory = new JwtKidIssuerCacheFactory();

        sendRefreshEvent(factory, ISSUER_1, jwkSet("kid-1"));
        sendRefreshEvent(factory, ISSUER_2, jwkSet("kid-2"));

        JwtKidIssuerCache cache = factory.getCache();
        assertThat(cache.lookupIssuer(tokenForKid("kid-1"))).isEqualTo(ISSUER_1);
        assertThat(cache.lookupIssuer(tokenForKid("kid-2"))).isEqualTo(ISSUER_2);
    }

    @Test
    void shouldDisableBothIssuersWhenTheyShareAKid() {
        JwtKidIssuerCacheFactory factory = new JwtKidIssuerCacheFactory();

        sendRefreshEvent(factory, ISSUER_1, jwkSet("shared-kid"));
        sendRefreshEvent(factory, ISSUER_2, jwkSet("shared-kid"));

        // Both issuers are disabled; no kid from either appears in the cache.
        assertThat(factory.getCache().lookupIssuer(tokenForKid("shared-kid"))).isNull();
    }

    @Test
    void shouldDisableAllKidsOfBothIssuersWhenTheyShareAnyKid() {
        // ISSUER_1 has kid-1 (unique) and shared-kid
        // ISSUER_2 has kid-2 (unique) and shared-kid
        // Both issuers are fully disabled because they share at least one kid.
        JwtKidIssuerCacheFactory factory = new JwtKidIssuerCacheFactory();

        sendRefreshEvent(factory, ISSUER_1, jwkSet("kid-1", "shared-kid"));
        sendRefreshEvent(factory, ISSUER_2, jwkSet("kid-2", "shared-kid"));

        JwtKidIssuerCache cache = factory.getCache();
        assertThat(cache.lookupIssuer(tokenForKid("kid-1"))).isNull();
        assertThat(cache.lookupIssuer(tokenForKid("kid-2"))).isNull();
        assertThat(cache.lookupIssuer(tokenForKid("shared-kid"))).isNull();
    }

    @Test
    void shouldKeepThirdIssuerCachedWhenTwoOtherIssuersShareAKid() {
        JwtKidIssuerCacheFactory factory = new JwtKidIssuerCacheFactory();

        sendRefreshEvent(factory, ISSUER_1, jwkSet("shared-kid"));
        sendRefreshEvent(factory, ISSUER_2, jwkSet("shared-kid"));
        sendRefreshEvent(factory, ISSUER_3, jwkSet("kid-3"));

        // ISSUER_1 and ISSUER_2 are disabled; ISSUER_3 remains cached.
        JwtKidIssuerCache cache = factory.getCache();
        assertThat(cache.lookupIssuer(tokenForKid("shared-kid"))).isNull();
        assertThat(cache.lookupIssuer(tokenForKid("kid-3"))).isEqualTo(ISSUER_3);
    }

    @Test
    void shouldUpdateCacheWhenJwkSetChanges() {
        JwtKidIssuerCacheFactory factory = new JwtKidIssuerCacheFactory();

        sendRefreshEvent(factory, ISSUER_1, jwkSet("kid-1"));
        sendRefreshEvent(factory, ISSUER_2, jwkSet("kid-2"));

        JwtKidIssuerCache cache = factory.getCache();
        assertThat(cache.lookupIssuer(tokenForKid("kid-1"))).isEqualTo(ISSUER_1);

        // Simulate key rotation for ISSUER_1.
        sendRefreshEvent(factory, ISSUER_1, jwkSet("kid-1-rotated"));
        assertThat(cache.lookupIssuer(tokenForKid("kid-1"))).isNull();
        assertThat(cache.lookupIssuer(tokenForKid("kid-1-rotated"))).isEqualTo(ISSUER_1);
    }

    @Test
    void shouldReEnableIssuersAfterRotationRemovesConflict() {
        JwtKidIssuerCacheFactory factory = new JwtKidIssuerCacheFactory();

        sendRefreshEvent(factory, ISSUER_1, jwkSet("shared-kid"));
        sendRefreshEvent(factory, ISSUER_2, jwkSet("shared-kid"));

        JwtKidIssuerCache cache = factory.getCache();
        assertThat(cache.lookupIssuer(tokenForKid("shared-kid"))).isNull();

        // ISSUER_2 rotates to a unique kid; conflict is resolved.
        sendRefreshEvent(factory, ISSUER_2, jwkSet("kid-2-unique"));
        assertThat(cache.lookupIssuer(tokenForKid("shared-kid"))).isEqualTo(ISSUER_1);
        assertThat(cache.lookupIssuer(tokenForKid("kid-2-unique"))).isEqualTo(ISSUER_2);
    }

    @Test
    void shouldSkipRecomputeWhenKidsAreUnchanged() {
        JwtKidIssuerCacheFactory factory = new JwtKidIssuerCacheFactory();

        sendRefreshEvent(factory, ISSUER_1, jwkSet("kid-1"));
        sendRefreshEvent(factory, ISSUER_2, jwkSet("kid-2"));

        JwtKidIssuerCache cache = factory.getCache();
        assertThat(cache.lookupIssuer(tokenForKid("kid-1"))).isEqualTo(ISSUER_1);

        // Send same JWK set (same kid) again — cache should remain consistent.
        sendRefreshEvent(factory, ISSUER_1, jwkSet("kid-1"));
        assertThat(cache.lookupIssuer(tokenForKid("kid-1"))).isEqualTo(ISSUER_1);
        assertThat(cache.lookupIssuer(tokenForKid("kid-2"))).isEqualTo(ISSUER_2);
    }

    @Test
    void shouldHandleScheduledRefreshCompletedEvent() {
        JwtKidIssuerCacheFactory factory = new JwtKidIssuerCacheFactory();

        sendScheduledRefreshEvent(factory, ISSUER_1, jwkSet("kid-1"));

        assertThat(factory.getCache().lookupIssuer(tokenForKid("kid-1"))).isEqualTo(ISSUER_1);
    }

    @Test
    void shouldLookupIssuerByTokenOnFirstCall() {
        JwtKidIssuerCacheFactory factory = new JwtKidIssuerCacheFactory();
        sendRefreshEvent(factory, ISSUER_1, jwkSet("kid-1"));
        sendRefreshEvent(factory, ISSUER_2, jwkSet("kid-2"));

        assertThat(factory.getCache().lookupIssuer(tokenForKid("kid-1"))).isEqualTo(ISSUER_1);
    }

    @Test
    void shouldCacheRawHeaderOnFirstLookupAndReturnDirectlyOnSubsequentCall() {
        JwtKidIssuerCacheFactory factory = new JwtKidIssuerCacheFactory();
        sendRefreshEvent(factory, ISSUER_1, jwkSet("kid-1"));
        sendRefreshEvent(factory, ISSUER_2, jwkSet("kid-2"));

        JwtKidIssuerCache cache = factory.getCache();
        String token = tokenForKid("kid-1");
        // First call: tier-2 (kid extraction)
        assertThat(cache.lookupIssuer(token)).isEqualTo(ISSUER_1);
        // Second call: tier-1 (raw header cache hit, no parsing)
        assertThat(cache.lookupIssuer(token)).isEqualTo(ISSUER_1);
    }

    @Test
    void shouldClearRawHeaderCacheOnKeyRotation() {
        JwtKidIssuerCacheFactory factory = new JwtKidIssuerCacheFactory();
        sendRefreshEvent(factory, ISSUER_1, jwkSet("kid-1"));
        sendRefreshEvent(factory, ISSUER_2, jwkSet("kid-2"));

        JwtKidIssuerCache cache = factory.getCache();
        String token = tokenForKid("kid-1");
        assertThat(cache.lookupIssuer(token)).isEqualTo(ISSUER_1);

        // Rotate kid for ISSUER_1; raw header cache must be cleared.
        sendRefreshEvent(factory, ISSUER_1, jwkSet("kid-1-rotated"));

        // Old token no longer resolves.
        assertThat(cache.lookupIssuer(token)).isNull();
        // New kid resolves (via tier-2 since tier-1 was cleared).
        assertThat(cache.lookupIssuer(tokenForKid("kid-1-rotated"))).isEqualTo(ISSUER_1);
    }

    @Test
    void shouldReturnNullForTokenWithNoKidInHeader() {
        JwtKidIssuerCacheFactory factory = new JwtKidIssuerCacheFactory();
        sendRefreshEvent(factory, ISSUER_1, jwkSet("kid-1"));

        // Token whose header has no kid field.
        String rawHeaderNoKid = new JWSHeader.Builder(JWSAlgorithm.RS256).build().toBase64URL().toString();
        String tokenNoKid = rawHeaderNoKid + ".payload.sig";
        assertThat(factory.getCache().lookupIssuer(tokenNoKid)).isNull();
    }

    // ---- helpers -----------------------------------------------------------

    @SuppressWarnings("unchecked")
    static void sendRefreshEvent(JwtKidIssuerCacheFactory factory, String issuer, JWKSet jwkSet) {
        CachingJWKSetSource.RefreshCompletedEvent<?> event =
                mock(CachingJWKSetSource.RefreshCompletedEvent.class);
        when(event.getJWKSet()).thenReturn(jwkSet);
        factory.createContext(issuer).notify(event);
    }

    @SuppressWarnings("unchecked")
    private static void sendScheduledRefreshEvent(JwtKidIssuerCacheFactory factory, String issuer, JWKSet jwkSet) {
        RefreshAheadCachingJWKSetSource.ScheduledRefreshCompletedEvent<?> event =
                mock(RefreshAheadCachingJWKSetSource.ScheduledRefreshCompletedEvent.class);
        when(event.getJWKSet()).thenReturn(jwkSet);
        factory.createContext(issuer).notify(event);
    }

    static JWKSet jwkSet(String... kids) {
        List<JWK> keys = new ArrayList<>();
        for (String kid : kids) {
            keys.add(new OctetSequenceKey.Builder(kidKeyContent(kid)).keyID(kid).build());
        }
        return new JWKSet(keys);
    }

    /** Returns a deterministic 16-byte key derived from the kid via MD5. */
    private static Base64URL kidKeyContent(String kid) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            return Base64URL.encode(md.digest(kid.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    /** Returns a raw base64url-encoded JWS header for {@code {"alg":"RS256","kid":"<kid>"}}. */
    static String rawHeaderForKid(String kid) {
        return new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(kid).build().toBase64URL().toString();
    }

    /** Returns a fake JWT token whose header carries the given kid. */
    static String tokenForKid(String kid) {
        return rawHeaderForKid(kid) + ".payload.sig";
    }
}
