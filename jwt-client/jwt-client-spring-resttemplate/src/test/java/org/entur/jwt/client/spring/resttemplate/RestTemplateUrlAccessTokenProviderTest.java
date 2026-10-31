package org.entur.jwt.client.spring.resttemplate;

import org.entur.jwt.client.AccessToken;
import org.entur.jwt.client.AccessTokenException;
import org.entur.jwt.client.AccessTokenUnavailableException;
import org.entur.jwt.client.AccessTokenRetryAfterException;
import org.entur.jwt.client.RetryingAccessTokenProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.MediaType;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.client.NoOpResponseErrorHandler;

import java.net.URL;
import java.util.Collections;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withResourceNotFound;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withServiceUnavailable;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withStatus;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withTooManyRequests;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withUnauthorizedRequest;

public class RestTemplateUrlAccessTokenProviderTest {

    private static final String ISSUE_URL = "https://entur.org/token";

    private static final String ISSUE_RESPONSE = "{\"access_token\":\"x.y.z\",\"expires_in\":86400,\"token_type\":\"Bearer\"}";

    private MockRestServiceServer mockServer;
    private RestTemplateUrlAccessTokenProvider provider;
    private RestTemplate restTemplate;

    @BeforeEach
    public void beforeEach() throws Exception {
        restTemplate = new RestTemplate();
        mockServer = MockRestServiceServer.bindTo(restTemplate).build();

        provider = new RestTemplateUrlAccessTokenProvider(restTemplate, new URL(ISSUE_URL), Map.of("grant_type", "client_credentials"), Collections.emptyMap()) {
            @Override
            protected long nanoTime() {
                return 0L;
            }
        };
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

    @ParameterizedTest
    @CsvSource({"429,false", "503,false", "429,true", "503,true"})
    public void shouldHonorRetryAfterWithEitherErrorHandler(int status, boolean noOpErrorHandler) {
        if (noOpErrorHandler) {
            restTemplate.setErrorHandler(new NoOpResponseErrorHandler());
        }
        mockServer.expect(requestTo(ISSUE_URL))
                .andRespond(withStatus(HttpStatusCode.valueOf(status)).header("Retry-After", "120"));
        RetryingAccessTokenProvider retrying = new RetryingAccessTokenProvider(provider);
        AccessTokenRetryAfterException failure = assertThrows(AccessTokenRetryAfterException.class,
                () -> retrying.getAccessToken(false));
        assertThat(failure.getRetryAfterDeadlineNanos()).isEqualTo(TimeUnit.SECONDS.toNanos(120));
        assertThat(failure.getHeaders()).containsExactly("Retry-After", "120");
        AccessTokenRetryAfterException rejected = assertThrows(AccessTokenRetryAfterException.class,
                () -> retrying.getAccessToken(true));
        assertThat(rejected.getRetryAfterDeadlineNanos()).isEqualTo(failure.getRetryAfterDeadlineNanos());
        mockServer.verify();
    }

    @ParameterizedTest
    @CsvSource({"429,text/html,<html>busy</html>", "503,text/html,<html>busy</html>", "429,application/json,{not json", "503,application/json,{not json"})
    public void shouldHonorRetryAfterWhenTheErrorBodyIsNotAToken(int status, String contentType, String body) {
        restTemplate.setErrorHandler(new NoOpResponseErrorHandler());
        mockServer.expect(requestTo(ISSUE_URL))
                .andRespond(withStatus(HttpStatusCode.valueOf(status)).contentType(MediaType.valueOf(contentType)).body(body).header("Retry-After", "120"));

        AccessTokenRetryAfterException failure = assertThrows(AccessTokenRetryAfterException.class, () -> provider.getAccessToken(false));

        assertThat(failure.getRetryAfterDeadlineNanos()).isEqualTo(TimeUnit.SECONDS.toNanos(120));
        assertThat(failure.getHeaders()).containsExactly("Retry-After", "120");
        mockServer.verify();
    }
}
