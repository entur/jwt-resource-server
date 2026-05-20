package org.entur.jwt.spring.config;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.source.CachingJWKSetSource;
import com.nimbusds.jose.util.Base64URL;
import org.entur.jwt.spring.JwtKidIssuerCache;
import org.entur.jwt.spring.JwtKidIssuerCacheFactory;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthenticationToken;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class JwtKidCachingReactiveAuthenticationManagerResolverTest {

    @Test
    void shouldResolveManagerByIssuerClaim() {
        ReactiveAuthenticationManager first = mock(ReactiveAuthenticationManager.class);
        ReactiveAuthenticationManager second = mock(ReactiveAuthenticationManager.class);
        IssuerAuthenticationManagerResolver issuerResolver = new IssuerAuthenticationManagerResolver(Map.of(
                "https://issuer-1.example", first,
                "https://issuer-2.example", second));

        JwtKidCachingReactiveAuthenticationManagerResolver resolver =
                new JwtKidCachingReactiveAuthenticationManagerResolver(issuerResolver,
                        emptyCache(Set.of("https://issuer-1.example", "https://issuer-2.example")));

        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/").header(HttpHeaders.AUTHORIZATION,
                        "Bearer " + token("{\"iss\":\"https://issuer-2.example\"}")).build());

        ReactiveAuthenticationManager manager = resolver.resolve(exchange).block();
        assertThat(manager).isNotNull();

        when(second.authenticate(any())).thenReturn(Mono.empty());
        BearerTokenAuthenticationToken token = new BearerTokenAuthenticationToken(
                token("{\"iss\":\"https://issuer-2.example\"}"));
        manager.authenticate(token).block();
        org.mockito.Mockito.verify(second).authenticate(token);
    }

    @Test
    void shouldReturnErrorForUnknownIssuer() {
        ReactiveAuthenticationManager first = mock(ReactiveAuthenticationManager.class);
        IssuerAuthenticationManagerResolver issuerResolver = new IssuerAuthenticationManagerResolver(Map.of(
                "https://issuer-1.example", first));

        JwtKidCachingReactiveAuthenticationManagerResolver resolver =
                new JwtKidCachingReactiveAuthenticationManagerResolver(issuerResolver,
                        emptyCache(Set.of("https://issuer-1.example")));

        ReactiveAuthenticationManager manager = resolver.resolve(
                MockServerWebExchange.from(MockServerHttpRequest.get("/").build())).block();

        BearerTokenAuthenticationToken token = new BearerTokenAuthenticationToken(
                token("{\"iss\":\"https://issuer-2.example\"}"));

        assertThat(manager).isNotNull();
        org.assertj.core.api.Assertions.assertThatThrownBy(() -> manager.authenticate(token).block())
                .isInstanceOf(InvalidBearerTokenException.class);
    }

    @Test
    void shouldUseKidCacheWhenAvailable() {
        ReactiveAuthenticationManager first = mock(ReactiveAuthenticationManager.class);
        ReactiveAuthenticationManager second = mock(ReactiveAuthenticationManager.class);
        Map<String, ReactiveAuthenticationManager> managers = Map.of(
                "https://issuer-1.example", first,
                "https://issuer-2.example", second);

        JwtKidIssuerCache cache = cacheWithKids(managers.keySet(),
                Map.of("https://issuer-1.example", "kid-1", "https://issuer-2.example", "kid-2"));

        IssuerAuthenticationManagerResolver issuerResolver = new IssuerAuthenticationManagerResolver(managers);
        JwtKidCachingReactiveAuthenticationManagerResolver resolver =
                new JwtKidCachingReactiveAuthenticationManagerResolver(issuerResolver, cache);

        // Token with kid=kid-2 and no iss claim.
        BearerTokenAuthenticationToken token = new BearerTokenAuthenticationToken(tokenForKid("kid-2"));

        ReactiveAuthenticationManager manager = resolver.resolve(
                MockServerWebExchange.from(MockServerHttpRequest.get("/").build())).block();

        when(second.authenticate(token)).thenReturn(Mono.empty());
        manager.authenticate(token).block();
        org.mockito.Mockito.verify(second).authenticate(token);
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
