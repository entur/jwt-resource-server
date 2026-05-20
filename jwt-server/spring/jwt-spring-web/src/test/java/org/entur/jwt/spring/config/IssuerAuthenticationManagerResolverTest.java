package org.entur.jwt.spring.config;

import jakarta.servlet.http.HttpServletRequest;
import org.entur.jwt.spring.JwtKidIssuerCache;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class IssuerAuthenticationManagerResolverTest {

    @Test
    void shouldResolveManagerByIssuerClaim() {
        AuthenticationManager first = mock(AuthenticationManager.class);
        AuthenticationManager second = mock(AuthenticationManager.class);
        IssuerAuthenticationManagerResolver resolver = new IssuerAuthenticationManagerResolver(Map.of(
                "https://issuer-1.example", first,
                "https://issuer-2.example", second));

        HttpServletRequest request = requestWithToken(token("{\"iss\":\"https://issuer-2.example\"}"));

        assertThat(resolver.resolve(request)).isSameAs(second);
    }

    @Test
    void shouldRejectUnknownIssuer() {
        AuthenticationManager first = mock(AuthenticationManager.class);
        IssuerAuthenticationManagerResolver resolver = new IssuerAuthenticationManagerResolver(Map.of(
                "https://issuer-1.example", first));

        HttpServletRequest request = requestWithToken(token("{\"iss\":\"https://issuer-2.example\"}"));

        assertThatThrownBy(() -> resolver.resolve(request)).isInstanceOf(InvalidBearerTokenException.class);
    }

    @Test
    void shouldResolveWhenIssuerContainsEscapedSlashes() {
        AuthenticationManager second = mock(AuthenticationManager.class);
        IssuerAuthenticationManagerResolver resolver = new IssuerAuthenticationManagerResolver(Map.of(
                "https://issuer-2.example", second));

        HttpServletRequest request = requestWithToken(token("{\"iss\":\"https:\\/\\/issuer-2.example\",\"sub\":\"a\"}"));

        assertThat(resolver.resolve(request)).isSameAs(second);
    }

    @Test
    void shouldResolveByHeaderKidWhenKidMappingIsUnique() {
        AuthenticationManager first = mock(AuthenticationManager.class);
        AuthenticationManager second = mock(AuthenticationManager.class);
        Map<String, AuthenticationManager> managers = Map.of(
                "https://issuer-1.example", first,
                "https://issuer-2.example", second);

        JwtKidIssuerCache cache = cacheWithKids(
                managers.keySet(),
                Map.of("https://issuer-1.example", "kid-1", "https://issuer-2.example", "kid-2"));

        IssuerAuthenticationManagerResolver resolver = new IssuerAuthenticationManagerResolver(managers, cache);

        HttpServletRequest request = requestWithToken(token("{\"sub\":\"a\"}", "{\"alg\":\"RS256\",\"kid\":\"kid-2\"}"));

        assertThat(resolver.resolve(request)).isSameAs(second);
    }

    // ---- helpers -----------------------------------------------------------

    @SuppressWarnings("unchecked")
    private static JwtKidIssuerCache cacheWithKids(Set<String> issuers, Map<String, String> issuerToKid) {
        JwtKidIssuerCache cache = new JwtKidIssuerCache(issuers);
        for (Map.Entry<String, String> entry : issuerToKid.entrySet()) {
            com.nimbusds.jose.jwk.source.CachingJWKSetSource.RefreshCompletedEvent<?> event =
                    mock(com.nimbusds.jose.jwk.source.CachingJWKSetSource.RefreshCompletedEvent.class);
            when(event.getJWKSet()).thenReturn(jwkSet(entry.getValue()));
            cache.listenerFor(entry.getKey()).notify(event);
        }
        return cache;
    }

    private static com.nimbusds.jose.jwk.JWKSet jwkSet(String kid) {
        com.nimbusds.jose.jwk.JWK key = new com.nimbusds.jose.jwk.OctetSequenceKey.Builder(
                new com.nimbusds.jose.util.Base64URL("AQIDBAUGBwgJCgsMDQ4PEA")).keyID(kid).build();
        return new com.nimbusds.jose.jwk.JWKSet(key);
    }

    private static HttpServletRequest requestWithToken(String token) {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("Authorization", "Bearer " + token);
        return request;
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
