package org.entur.jwt.client.spring.webflux;

import org.entur.jwt.client.AccessToken;
import org.entur.jwt.client.AccessTokenUnavailableException;
import org.entur.jwt.client.AccessTokenRetryAfterException;
import org.entur.jwt.client.RetryingAccessTokenProvider;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.net.URL;
import java.util.Collections;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class WebClientUrlAccessTokenProviderTest {

    private static final String ISSUE_URL = "https://entur.org/token";

    private static final String ISSUE_RESPONSE = "{\"access_token\":\"x.y.z\",\"expires_in\":86400,\"token_type\":\"Bearer\"}";

    private WebClientUrlAccessTokenProvider provider(ClientResponse response) throws Exception {
        WebClient webClient = WebClient.builder()
                .exchangeFunction(request -> Mono.just(response))
                .build();

        return new WebClientUrlAccessTokenProvider(webClient, new URL(ISSUE_URL), Map.of("grant_type", "client_credentials"), Collections.emptyMap());
    }

    @Test
    public void shouldReturnAccessToken() throws Exception {
        ClientResponse response = ClientResponse.create(HttpStatus.OK)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                .body(ISSUE_RESPONSE)
                .build();

        AccessToken accessToken = provider(response).getAccessToken(false);

        assertThat(accessToken.getValue()).isEqualTo("x.y.z");
        assertThat(accessToken.getType()).isEqualTo("Bearer");
    }

    @Test
    public void shouldThrowAccessTokenUnavailableExceptionWhenResponseIsEmpty() throws Exception {
        WebClientUrlAccessTokenProvider provider = provider(ClientResponse.create(HttpStatus.OK).build());

        assertThrows(AccessTokenUnavailableException.class, () -> {
            provider.getAccessToken(false);
        });
    }

    @ParameterizedTest
    @ValueSource(ints = {429, 503})
    public void shouldHonorRetryAfterWithoutSendingAnotherRequest(int status) throws Exception {
        AtomicInteger requests = new AtomicInteger();
        WebClient client = WebClient.builder().exchangeFunction(request -> {
            requests.incrementAndGet();
            return Mono.just(ClientResponse.create(HttpStatus.valueOf(status)).header("Retry-After", "120").build());
        }).build();
        WebClientUrlAccessTokenProvider http = new WebClientUrlAccessTokenProvider(client, new URL(ISSUE_URL), Map.of(), Map.of()) {
            @Override
            protected long nanoTime() {
                return 0L;
            }
        };
        RetryingAccessTokenProvider provider = new RetryingAccessTokenProvider(http);
        AccessTokenRetryAfterException failure = assertThrows(AccessTokenRetryAfterException.class,
                () -> provider.getAccessToken(false));
        assertThat(failure.getRetryAfterDeadlineNanos()).isEqualTo(TimeUnit.SECONDS.toNanos(120));
        assertThat(failure.getHeaders()).containsExactly("Retry-After", "120");
        AccessTokenRetryAfterException rejected = assertThrows(AccessTokenRetryAfterException.class,
                () -> provider.getAccessToken(true));
        assertThat(rejected.getRetryAfterDeadlineNanos()).isEqualTo(failure.getRetryAfterDeadlineNanos());
        assertThat(requests.get()).isEqualTo(1);
    }
}
