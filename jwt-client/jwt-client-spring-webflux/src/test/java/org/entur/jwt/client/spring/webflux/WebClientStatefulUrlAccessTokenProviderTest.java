package org.entur.jwt.client.spring.webflux;

import org.entur.jwt.client.AccessTokenUnavailableException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.net.URL;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Deque;
import java.util.List;
import java.util.Map;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class WebClientStatefulUrlAccessTokenProviderTest {

    private static final String ISSUE_URL = "https://entur.org/token";
    private static final String REFRESH_URL = "https://entur.org/refresh";
    private static final String REVOKE_URL = "https://entur.org/logout";

    private static final String ISSUE_RESPONSE = "{\"access_token\":\"x.y.z\",\"expires_in\":86400,\"token_type\":\"Bearer\",\"refresh_token\":\"a.b.c\",\"refresh_expires_in\":604800}";
    private static final String REISSUE_RESPONSE = "{\"access_token\":\"a1.b1.c1\",\"expires_in\":86400,\"token_type\":\"Bearer\",\"refresh_token\":\"a2.b2.c2\",\"refresh_expires_in\":604800}";

    private final Deque<ClientResponse> responses = new ArrayDeque<>();
    private final List<URI> requests = new ArrayList<>();

    private WebClientStatefulUrlAccessTokenProvider provider;

    @BeforeEach
    public void beforeEach() throws Exception {
        WebClient webClient = WebClient.builder()
                .exchangeFunction(request -> {
                    requests.add(request.url());
                    return Mono.just(responses.removeFirst());
                })
                .build();

        provider = new WebClientStatefulUrlAccessTokenProvider(webClient, new URL(ISSUE_URL), Map.of("grant_type", "client_credentials"), Collections.emptyMap(), new URL(REFRESH_URL), new URL(REVOKE_URL));
    }

    private void respond(HttpStatus status, String json) {
        ClientResponse.Builder builder = ClientResponse.create(status);
        if (json != null) {
            builder.header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE).body(json);
        }
        responses.add(builder.build());
    }

    @Test
    public void shouldIssueNewTokenWhenRefreshTokenIsRejected() throws Exception {
        respond(HttpStatus.OK, ISSUE_RESPONSE);
        // i.e. the session has been revoked or has expired
        respond(HttpStatus.BAD_REQUEST, "{\"error\":\"invalid_grant\"}");
        respond(HttpStatus.OK, REISSUE_RESPONSE);

        assertThat(provider.getAccessToken(false).getValue()).isEqualTo("x.y.z");
        assertThat(provider.getRefreshToken().getValue()).isEqualTo("a.b.c");

        assertThat(provider.getAccessToken(true).getValue()).isEqualTo("a1.b1.c1");
        assertThat(provider.getRefreshToken().getValue()).isEqualTo("a2.b2.c2");

        assertThat(requests).containsExactly(URI.create(ISSUE_URL), URI.create(REFRESH_URL), URI.create(ISSUE_URL)).inOrder();
    }

    @Test
    public void shouldNotIssueNewTokenWhenRefreshIsTemporarilyUnavailable() throws Exception {
        respond(HttpStatus.OK, ISSUE_RESPONSE);
        respond(HttpStatus.SERVICE_UNAVAILABLE, null);

        provider.getAccessToken(false);

        assertThrows(AccessTokenUnavailableException.class, () -> {
            provider.getAccessToken(true);
        });
        // keep the session for the next attempt
        assertThat(provider.getRefreshToken().getValue()).isEqualTo("a.b.c");

        assertThat(requests).containsExactly(URI.create(ISSUE_URL), URI.create(REFRESH_URL)).inOrder();
    }
}
