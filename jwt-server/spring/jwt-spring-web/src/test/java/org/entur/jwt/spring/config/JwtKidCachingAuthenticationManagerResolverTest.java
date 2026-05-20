package org.entur.jwt.spring.config;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.source.CachingJWKSetSource;
import com.nimbusds.jose.util.Base64URL;
import jakarta.servlet.http.HttpServletRequest;
import org.entur.jwt.spring.JwtKidIssuerCache;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthenticationToken;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class JwtKidCachingAuthenticationManagerResolverTest {

    @Test
    void shouldResolveManagerByIssuerClaim() {
        AuthenticationManager first = mock(AuthenticationManager.class);
        AuthenticationManager second = mock(AuthenticationManager.class);
        IssuerAuthenticationManagerResolver issuerResolver = new IssuerAuthenticationManagerResolver(Map.of(
                "https://issuer-1.example", first,
                "https://issuer-2.example", second));

        JwtKidCachingAuthenticationManagerResolver resolver = new JwtKidCachingAuthenticationManagerResolver(
                issuerResolver, new JwtKidIssuerCache(Set.of("https://issuer-1.example", "https://issuer-2.example")));

        // Cache not yet populated → falls back to iss claim
        BearerTokenAuthenticationToken token = new BearerTokenAuthenticationToken(
                token("{\"iss\":\"https://issuer-2.example\"}"));
        AuthenticationManager manager = resolver.resolve(mock(HttpServletRequest.class));
        assertThat(manager).isNotNull();

        // The ResolvingAuthenticationManager should delegate to the correct per-issuer manager.
        // We verify by checking that calling authenticate on the resolved manager calls through
        // to 'second' (which we stub to return null – just enough to avoid NPE).
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
                issuerResolver, new JwtKidIssuerCache(Set.of("https://issuer-1.example")));

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
                token("{}", "{\"alg\":\"RS256\",\"kid\":\"kid-2\"}"));
        AuthenticationManager manager = resolver.resolve(mock(HttpServletRequest.class));

        when(second.authenticate(token)).thenReturn(null);
        manager.authenticate(token);
        org.mockito.Mockito.verify(second).authenticate(token);
    }

    // ---- helpers -----------------------------------------------------------

    @SuppressWarnings("unchecked")
    private static JwtKidIssuerCache cacheWithKids(Set<String> issuers, Map<String, String> issuerToKid) {
        JwtKidIssuerCache cache = new JwtKidIssuerCache(issuers);
        for (Map.Entry<String, String> entry : issuerToKid.entrySet()) {
            CachingJWKSetSource.RefreshCompletedEvent<?> event =
                    mock(CachingJWKSetSource.RefreshCompletedEvent.class);
            when(event.getJWKSet()).thenReturn(jwkSet(entry.getValue()));
            cache.listenerFor(entry.getKey()).notify(event);
        }
        return cache;
    }

    private static JWKSet jwkSet(String kid) {
        JWK key = new OctetSequenceKey.Builder(new Base64URL("AQIDBAUGBwgJCgsMDQ4PEA")).keyID(kid).build();
        return new JWKSet(key);
    }

    private static String token(String payloadJson) {
        return token(payloadJson, "{\"alg\":\"RS256\"}");
    }

    private static String token(String payloadJson, String headerJson) {
        String header = Base64.getUrlEncoder().withoutPadding().encodeToString(headerJson.getBytes(StandardCharsets.UTF_8));
        String payload = Base64.getUrlEncoder().withoutPadding().encodeToString(payloadJson.getBytes(StandardCharsets.UTF_8));
        return header + "." + payload + ".sig";
    }
}
