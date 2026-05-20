package org.entur.jwt.spring.config;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.server.ServerWebExchange;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;

class IssuerAuthenticationManagerResolverTest {

    @Test
    void shouldResolveManagerByIssuerClaim() {
        ReactiveAuthenticationManager first = mock(ReactiveAuthenticationManager.class);
        ReactiveAuthenticationManager second = mock(ReactiveAuthenticationManager.class);
        IssuerAuthenticationManagerResolver resolver = new IssuerAuthenticationManagerResolver(Map.of(
                "https://issuer-1.example", first,
                "https://issuer-2.example", second));

        ServerWebExchange exchange = exchangeWithToken(token("{\"iss\":\"https://issuer-2.example\"}"));

        assertThat(resolver.resolve(exchange).block()).isSameAs(second);
    }

    @Test
    void shouldRejectUnknownIssuer() {
        ReactiveAuthenticationManager first = mock(ReactiveAuthenticationManager.class);
        IssuerAuthenticationManagerResolver resolver = new IssuerAuthenticationManagerResolver(Map.of(
                "https://issuer-1.example", first));

        ServerWebExchange exchange = exchangeWithToken(token("{\"iss\":\"https://issuer-2.example\"}"));

        assertThatThrownBy(() -> resolver.resolve(exchange).block()).isInstanceOf(InvalidBearerTokenException.class);
    }

    private static ServerWebExchange exchangeWithToken(String token) {
        return MockServerWebExchange.from(MockServerHttpRequest.get("http://localhost/protected")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .build());
    }

    private static String token(String payloadJson) {
        String header = Base64.getUrlEncoder().withoutPadding().encodeToString("{\"alg\":\"none\"}".getBytes(StandardCharsets.UTF_8));
        String payload = Base64.getUrlEncoder().withoutPadding().encodeToString(payloadJson.getBytes(StandardCharsets.UTF_8));
        return header + "." + payload + ".sig";
    }
}
