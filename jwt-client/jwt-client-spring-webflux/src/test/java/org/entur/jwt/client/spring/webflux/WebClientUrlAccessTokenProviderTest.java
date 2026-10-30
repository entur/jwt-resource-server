package org.entur.jwt.client.spring.webflux;

import org.entur.jwt.client.AccessToken;
import org.entur.jwt.client.AccessTokenUnavailableException;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.net.URL;
import java.util.Collections;
import java.util.Map;

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
}
