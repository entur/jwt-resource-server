package org.entur.jwt.spring.issuer;

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests for JwkHeaderToIssuerEventListeners and related classes,
 * asserting correct cache-enable/disable behaviour based on KID uniqueness.
 */
class JwkHeaderToIssuerEventListenersTest {

    // ------------------------------------------------------------------ cache enable/disable

    @Test
    void cacheEnabledWhenAllIssuersHaveUniqueKids() {
        JwtHeaderToIssuerMapper mapper = new JwtHeaderToIssuerMapper();
        JwkHeaderToIssuerEventListeners listeners = new JwkHeaderToIssuerEventListeners(2, mapper);

        // Initially the cache is disabled
        assertFalse(mapper.isEnabled());
        assertFalse(mapper.isEnabled("issuer1"));
        assertFalse(mapper.isEnabled("issuer2"));

        // Only one issuer has reported – still disabled
        listeners.setIssuerJwkKids("issuer1", Set.of("kid1", "kid2"));
        assertFalse(mapper.isEnabled());

        // Second issuer reports non-overlapping KIDs – cache should now be active
        listeners.setIssuerJwkKids("issuer2", Set.of("kid3", "kid4"));

        assertTrue(mapper.isEnabled());
        assertTrue(mapper.isEnabled("issuer1"));
        assertTrue(mapper.isEnabled("issuer2"));
    }

    @Test
    void cacheRemainsDisabledWhenKidsOverlap() {
        JwtHeaderToIssuerMapper mapper = new JwtHeaderToIssuerMapper();
        JwkHeaderToIssuerEventListeners listeners = new JwkHeaderToIssuerEventListeners(2, mapper);

        // Both issuers share "kid2"
        listeners.setIssuerJwkKids("issuer1", Set.of("kid1", "kid2"));
        listeners.setIssuerJwkKids("issuer2", Set.of("kid2", "kid3"));

        // No issuer should be eligible for fast-path caching
        assertFalse(mapper.isEnabled());
        assertFalse(mapper.isEnabled("issuer1"));
        assertFalse(mapper.isEnabled("issuer2"));
    }

    @Test
    void cacheRemainsDisabledWhenBothIssuersHaveMissingKids() {
        JwtHeaderToIssuerMapper mapper = new JwtHeaderToIssuerMapper();
        JwkHeaderToIssuerEventListeners listeners = new JwkHeaderToIssuerEventListeners(2, mapper);

        // Keys without a KID are represented by the sentinel string "null"
        listeners.setIssuerJwkKids("issuer1", Set.of("null"));
        listeners.setIssuerJwkKids("issuer2", Set.of("null"));

        // Both sets contain the "null" sentinel, so they overlap → cache disabled
        assertFalse(mapper.isEnabled());
        assertFalse(mapper.isEnabled("issuer1"));
        assertFalse(mapper.isEnabled("issuer2"));
    }

    @Test
    void cacheNotEnabledUntilAllIssuersHaveReported() {
        JwtHeaderToIssuerMapper mapper = new JwtHeaderToIssuerMapper();
        // Three issuers required
        JwkHeaderToIssuerEventListeners listeners = new JwkHeaderToIssuerEventListeners(3, mapper);

        listeners.setIssuerJwkKids("issuer1", Set.of("kid1"));
        assertFalse(mapper.isEnabled());

        listeners.setIssuerJwkKids("issuer2", Set.of("kid2"));
        assertFalse(mapper.isEnabled());

        listeners.setIssuerJwkKids("issuer3", Set.of("kid3"));
        assertTrue(mapper.isEnabled());
    }

    // ------------------------------------------------------------------ extractKids

    @Test
    void extractKidsWithExplicitKid() throws Exception {
        var key = new ECKeyGenerator(Curve.P_256).keyID("my-kid").generate();
        Set<String> kids = JwkHeaderToIssuerEventListener.extractKids(new JWKSet(key));

        assertEquals(Set.of("my-kid"), kids);
    }

    @Test
    void extractKidsWithNullKid() throws Exception {
        // Key generated without an explicit key ID
        var key = new ECKeyGenerator(Curve.P_256).generate();
        Set<String> kids = JwkHeaderToIssuerEventListener.extractKids(new JWKSet(key));

        // A null KID is represented by the sentinel string "null"
        assertEquals(Set.of("null"), kids);
    }
}
