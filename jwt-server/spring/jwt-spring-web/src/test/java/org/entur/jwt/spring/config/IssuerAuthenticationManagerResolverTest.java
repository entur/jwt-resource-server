package org.entur.jwt.spring.config;

import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;

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

    private static HttpServletRequest requestWithToken(String token) {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("Authorization", "Bearer " + token);
        return request;
    }

    private static String token(String payloadJson) {
        String header = Base64.getUrlEncoder().withoutPadding().encodeToString("{\"alg\":\"none\"}".getBytes(StandardCharsets.UTF_8));
        String payload = Base64.getUrlEncoder().withoutPadding().encodeToString(payloadJson.getBytes(StandardCharsets.UTF_8));
        return header + "." + payload + ".sig";
    }
}
