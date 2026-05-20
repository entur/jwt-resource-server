package org.entur.jwt.spring.config;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.CachingJWKSetSource;
import jakarta.servlet.http.HttpServletRequest;
import org.entur.jwt.spring.JwtKidIssuerCache;
import org.entur.jwt.spring.JwtKidIssuerCacheFactory;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthenticationToken;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.util.Base64URL;

class JwtKidCachingAuthenticationManagerResolverTest {

    @Test
    void shouldResolveManagerByIssuerClaim() {
        AuthenticationManager first = mock(AuthenticationManager.class);
        AuthenticationManager second = mock(AuthenticationManager.class);
        IssuerAuthenticationManagerResolver issuerResolver = new IssuerAuthenticationManagerResolver(Map.of(
                "https://issuer-1.example", first,
                "https://issuer-2.example", second));

        JwtKidCachingAuthenticationManagerResolver resolver = new JwtKidCachingAuthenticationManagerResolver(
                issuerResolver, emptyCache(Set.of("https://issuer-1.example", "https://issuer-2.example")));

        // Cache not yet populated → falls back to iss claim
        BearerTokenAuthenticationToken token = new BearerTokenAuthenticationToken(
                token("{\"iss\":\"https://issuer-2.example\"}"));
        AuthenticationManager manager = resolver.resolve(mock(HttpServletRequest.class));
        assertThat(manager).isNotNull();

        // The ResolvingAuthenticationManager should delegate to the correct per-issuer manager.
        when(second.authenticate(token)).thenReturn(null);
        manager.authenticate(token);
        org.mockito.Mockito.verify(second).authenticate(token);
    }

    @Test
    void shouldRejectUnknownIssuer() {
        AuthenticationManager first = mock(AuthenticationManager.class);
        IssuerAuthenticationManagerResolver issuerResolver = new IssuerAuthenticationManagerResolver(Map.of(
                "https://issuer-1.example", first));

        JwtKidCachingAuthenticationManagerResolver resolver = new JwtKidCachingAuthenticationManagerResolver(
                issuerResolver, emptyCache(Set.of("https://issuer-1.example")));

        BearerTokenAuthenticationToken token = new BearerTokenAuthenticationToken(
                token("{\"iss\":\"https://issuer-2.example\"}"));
        AuthenticationManager manager = resolver.resolve(mock(HttpServletRequest.class));

        assertThatThrownBy(() -> manager.authenticate(token))
                .isInstanceOf(InvalidBearerTokenException.class);
    }

    @Test
    void shouldUseKidCacheWhenAvailable() {
        AuthenticationManager first = mock(AuthenticationManager.class);
        AuthenticationManager second = mock(AuthenticationManager.class);
        Map<String, AuthenticationManager> managers = Map.of(
                "https://issuer-1.example", first,
                "https://issuer-2.example", second);

        JwtKidIssuerCache cache = cacheWithKids(managers.keySet(),
                Map.of("https://issuer-1.example", "kid-1", "https://issuer-2.example", "kid-2"));

        IssuerAuthenticationManagerResolver issuerResolver = new IssuerAuthenticationManagerResolver(managers);
        JwtKidCachingAuthenticationManagerResolver resolver =
                new JwtKidCachingAuthenticationManagerResolver(issuerResolver, cache);

        // Token with kid=kid-2 and no iss claim - only the kid cache can route it.
        BearerTokenAuthenticationToken token = new BearerTokenAuthenticationToken(
                tokenForKid("kid-2"));
        AuthenticationManager manager = resolver.resolve(mock(HttpServletRequest.class));

        when(second.authenticate(token)).thenReturn(null);
        manager.authenticate(token);
        org.mockito.Mockito.verify(second).authenticate(token);
    }

    @Test
    void shouldUseRawHeaderCacheOnSecondCallForSameToken() {
        AuthenticationManager first = mock(AuthenticationManager.class);
        AuthenticationManager second = mock(AuthenticationManager.class);
        Map<String, AuthenticationManager> managers = Map.of(
                "https://issuer-1.example", first,
                "https://issuer-2.example", second);

        JwtKidIssuerCache cache = cacheWithKids(managers.keySet(),
                Map.of("https://issuer-1.example", "kid-1", "https://issuer-2.example", "kid-2"));

        IssuerAuthenticationManagerResolver issuerResolver = new IssuerAuthenticationManagerResolver(managers);
        JwtKidCachingAuthenticationManagerResolver resolver =
                new JwtKidCachingAuthenticationManagerResolver(issuerResolver, cache);

        // Token with kid=kid-1 and no iss claim.
        BearerTokenAuthenticationToken token = new BearerTokenAuthenticationToken(tokenForKid("kid-1"));
        AuthenticationManager manager = resolver.resolve(mock(HttpServletRequest.class));

        when(first.authenticate(token)).thenReturn(null);
        // First call: tier-2 (kid extraction from raw header, populates tier-1).
        manager.authenticate(token);
        // Second call: tier-1 (raw header string lookup, no parsing needed).
        manager.authenticate(token);
        org.mockito.Mockito.verify(first, org.mockito.Mockito.times(2)).authenticate(token);
    }

    // ---- helpers -----------------------------------------------------------

    /** Returns a cache backed by a factory with no events sent yet (empty kid map). */
    private static JwtKidIssuerCache emptyCache(Set<String> issuers) {
        JwtKidIssuerCacheFactory factory = new JwtKidIssuerCacheFactory();
        issuers.forEach(factory::createContext);
        return factory.getCache();
    }

    @SuppressWarnings("unchecked")
    private static JwtKidIssuerCache cacheWithKids(Set<String> issuers, Map<String, String> issuerToKid) {
        JwtKidIssuerCacheFactory factory = new JwtKidIssuerCacheFactory();
        issuers.forEach(factory::createContext);
        for (Map.Entry<String, String> entry : issuerToKid.entrySet()) {
            CachingJWKSetSource.RefreshCompletedEvent<?> event =
                    mock(CachingJWKSetSource.RefreshCompletedEvent.class);
            when(event.getJWKSet()).thenReturn(jwkSet(entry.getValue()));
            factory.createContext(entry.getKey()).notify(event);
        }
        return factory.getCache();
    }

    private static JWKSet jwkSet(String kid) {
        JWK key = new OctetSequenceKey.Builder(kidKeyContent(kid)).keyID(kid).build();
        return new JWKSet(key);
    }

    private static Base64URL kidKeyContent(String kid) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            return Base64URL.encode(md.digest(kid.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    /** Returns a fake JWT token whose header carries the given kid. */
    private static String tokenForKid(String kid) {
        String rawHeader = new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(kid).build().toBase64URL().toString();
        return rawHeader + ".payload.sig";
    }

    private static String token(String payloadJson) {
        return token(payloadJson, "{\"alg\":\"RS256\"}");
    }

    private static String token(String payloadJson, String headerJson) {
        String header = java.util.Base64.getUrlEncoder().withoutPadding()
                .encodeToString(headerJson.getBytes(StandardCharsets.UTF_8));
        String payload = java.util.Base64.getUrlEncoder().withoutPadding()
                .encodeToString(payloadJson.getBytes(StandardCharsets.UTF_8));
        return header + "." + payload + ".sig";
    }
}
