package org.entur.jwt.client.spring.resttemplate;

import org.entur.jwt.client.AccessToken;
import org.entur.jwt.client.AccessTokenException;
import org.entur.jwt.client.AccessTokenUnavailableException;
import org.entur.jwt.client.RetryingAccessTokenProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestTemplate;

import java.net.URL;
import java.util.Collections;
import java.util.Map;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withResourceNotFound;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withServiceUnavailable;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withTooManyRequests;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withUnauthorizedRequest;

public class RestTemplateUrlAccessTokenProviderTest {

    private static final String ISSUE_URL = "https://entur.org/token";

    private static final String ISSUE_RESPONSE = "{\"access_token\":\"x.y.z\",\"expires_in\":86400,\"token_type\":\"Bearer\"}";

    private MockRestServiceServer mockServer;
    private RestTemplateUrlAccessTokenProvider provider;

    @BeforeEach
    public void beforeEach() throws Exception {
        RestTemplate restTemplate = new RestTemplate();
        mockServer = MockRestServiceServer.bindTo(restTemplate).build();

        provider = new RestTemplateUrlAccessTokenProvider(restTemplate, new URL(ISSUE_URL), Map.of("grant_type", "client_credentials"), Collections.emptyMap());
    }

    @Test
    public void shouldReturnAccessToken() throws Exception {
        mockServer.expect(requestTo(ISSUE_URL))
                .andExpect(method(HttpMethod.POST))
                .andRespond(withSuccess(ISSUE_RESPONSE, MediaType.APPLICATION_JSON));

        AccessToken accessToken = provider.getAccessToken(false);

        assertThat(accessToken.getValue()).isEqualTo("x.y.z");
        assertThat(accessToken.getType()).isEqualTo("Bearer");

        mockServer.verify();
    }

    @Test
    public void shouldThrowAccessTokenUnavailableExceptionWhenResponseIsEmpty() {
        mockServer.expect(requestTo(ISSUE_URL))
                .andExpect(method(HttpMethod.POST))
                .andRespond(withSuccess());

        assertThrows(AccessTokenUnavailableException.class, () -> {
            provider.getAccessToken(false);
        });

        mockServer.verify();
    }

    @Test
    public void shouldThrowAccessTokenExceptionOnHttp401() {
        mockServer.expect(requestTo(ISSUE_URL))
                .andExpect(method(HttpMethod.POST))
                .andRespond(withUnauthorizedRequest());

        AccessTokenException e = assertThrows(AccessTokenException.class, () -> {
            provider.getAccessToken(false);
        });
        assertThat(e).isNotInstanceOf(AccessTokenUnavailableException.class);
        assertThat(e).hasMessageThat().contains("401");

        mockServer.verify();
    }

    @Test
    public void shouldNotRetryOnHttp404() {
        // i.e. wrong path is a permanent error, so expect a single request
        mockServer.expect(requestTo(ISSUE_URL))
                .andExpect(method(HttpMethod.POST))
                .andRespond(withResourceNotFound());

        RetryingAccessTokenProvider retryingProvider = new RetryingAccessTokenProvider(provider);

        AccessTokenException e = assertThrows(AccessTokenException.class, () -> {
            retryingProvider.getAccessToken(false);
        });
        assertThat(e).isNotInstanceOf(AccessTokenUnavailableException.class);

        mockServer.verify();
    }

    @Test
    public void shouldThrowAccessTokenUnavailableExceptionOnHttp503() {
        mockServer.expect(requestTo(ISSUE_URL))
                .andExpect(method(HttpMethod.POST))
                .andRespond(withServiceUnavailable().header(HttpHeaders.RETRY_AFTER, "120"));

        AccessTokenUnavailableException e = assertThrows(AccessTokenUnavailableException.class, () -> {
            provider.getAccessToken(false);
        });
        assertThat(e).hasMessageThat().contains("Retry-After:120");

        mockServer.verify();
    }

    @Test
    public void shouldThrowAccessTokenUnavailableExceptionOnHttp429() {
        mockServer.expect(requestTo(ISSUE_URL))
                .andExpect(method(HttpMethod.POST))
                .andRespond(withTooManyRequests().header("X-RateLimit-Reset", "1700000000"));

        AccessTokenUnavailableException e = assertThrows(AccessTokenUnavailableException.class, () -> {
            provider.getAccessToken(false);
        });
        assertThat(e).hasMessageThat().contains("X-RateLimit-Reset:1700000000");

        mockServer.verify();
    }
}
