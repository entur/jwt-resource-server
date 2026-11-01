package org.entur.jwt.client.spring.webflux;

import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.entur.jwt.client.AccessTokenUnavailableException;
import org.entur.jwt.client.AccessTokenRetryAfterException;
import org.entur.jwt.client.AuthorizationHeaderUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
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
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

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
    private long nowNanos;

    @BeforeEach
    public void beforeEach() throws Exception {
        WebClient webClient = WebClient.builder()
                .exchangeFunction(request -> {
                    requests.add(request.url());
                    return Mono.just(responses.removeFirst());
                })
                .build();

        provider = new WebClientStatefulUrlAccessTokenProvider(webClient, new URL(ISSUE_URL), Map.of("grant_type", "client_credentials"), Collections.emptyMap(),
                new URL(REFRESH_URL), new URL(REVOKE_URL)) {
            @Override
            protected long nanoTime() {
                return nowNanos;
            }
        };
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

        assertThrows(AccessTokenRetryAfterException.class, () -> provider.getAccessToken(true));
        assertThat(provider.getRefreshToken()).isNull();
        nowNanos += TimeUnit.SECONDS.toNanos(15);
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

    @ParameterizedTest
    @ValueSource(ints = {500, 502, 504})
    public void shouldKeepRefreshTokenWhenRefreshFailsWithServerError(int status) throws Exception {
        respond(HttpStatus.OK, ISSUE_RESPONSE);
        respond(HttpStatus.valueOf(status), null);
        respond(HttpStatus.OK, REISSUE_RESPONSE);

        provider.getAccessToken(false);

        assertThrows(AccessTokenRetryAfterException.class, () -> provider.getAccessToken(true));
        // a server error says nothing about the session
        assertThat(provider.getRefreshToken().getValue()).isEqualTo("a.b.c");
        nowNanos += TimeUnit.SECONDS.toNanos(15);
        assertThat(provider.getAccessToken(true).getValue()).isEqualTo("a1.b1.c1");

        assertThat(requests).containsExactly(URI.create(ISSUE_URL), URI.create(REFRESH_URL), URI.create(REFRESH_URL)).inOrder();
    }

    @ParameterizedTest
    @CsvSource({"429,false", "503,false", "429,true", "503,true"})
    public void shouldHonorRetryAfterForIssueAndRefresh(int status, boolean refreshing) throws Exception {
        if (refreshing) {
            respond(HttpStatus.OK, ISSUE_RESPONSE);
            provider.getAccessToken(false);
        }
        responses.add(ClientResponse.create(HttpStatus.valueOf(status)).header("Retry-After", "120").build());
        var original = provider.getRefreshToken();
        AccessTokenRetryAfterException failure = assertThrows(AccessTokenRetryAfterException.class,
                () -> provider.getAccessToken(false));
        assertThat(failure.getRetryAfterDeadlineNanos() - nowNanos).isEqualTo(TimeUnit.SECONDS.toNanos(120));
        assertThat(failure.getHeaders()).containsExactly("Retry-After", "120");
        assertThrows(AccessTokenRetryAfterException.class, () -> provider.getAccessToken(true));
        assertThat(provider.getRefreshToken()).isSameInstanceAs(original);
        assertThat(requests).hasSize(refreshing ? 2 : 1);
        assertThat(requests.get(requests.size() - 1)).isEqualTo(URI.create(refreshing ? REFRESH_URL : ISSUE_URL));
        nowNanos = TimeUnit.SECONDS.toNanos(15);
        assertThrows(AccessTokenRetryAfterException.class, () -> provider.getAccessToken(false));
        nowNanos = TimeUnit.SECONDS.toNanos(120);
        respond(HttpStatus.OK, REISSUE_RESPONSE);
        assertThat(provider.getAccessToken(false).getValue()).isEqualTo("a1.b1.c1");
        assertThat(requests).hasSize(refreshing ? 3 : 2);
        assertThat(requests.get(requests.size() - 1)).isEqualTo(URI.create(refreshing ? REFRESH_URL : ISSUE_URL));
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    public void shouldCancelTheRequestWhenTheCallerIsInterrupted(boolean refreshing) throws Exception {
        CountDownLatch subscribed = new CountDownLatch(1);
        CountDownLatch cancelled = new CountDownLatch(1);
        ClientResponse issued = ClientResponse.create(HttpStatus.OK).header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE).body(ISSUE_RESPONSE).build();
        WebClient client = WebClient.builder().exchangeFunction(request -> refreshing && ISSUE_URL.equals(request.url().toString()) ? Mono.just(issued) :
                Mono.<ClientResponse>never().doOnSubscribe(subscription -> subscribed.countDown()).doOnCancel(cancelled::countDown)).build();
        WebClientStatefulUrlAccessTokenProvider http = new WebClientStatefulUrlAccessTokenProvider(client, new URL(ISSUE_URL), Map.of(), Map.of(),
                new URL(REFRESH_URL), new URL(REVOKE_URL));
        if (refreshing) {
            http.getAccessToken(false);
        }
        AtomicReference<Throwable> failure = new AtomicReference<>();
        Thread caller = new Thread(() -> {
            try {
                http.getAccessToken(false);
            } catch (Throwable e) {
                failure.set(e);
            }
        });
        caller.start();
        assertThat(subscribed.await(10, TimeUnit.SECONDS)).isTrue();
        caller.interrupt();
        caller.join(10_000);
        assertThat(caller.isAlive()).isFalse();
        assertThat(cancelled.await(10, TimeUnit.SECONDS)).isTrue();
        assertThat(failure.get()).isInstanceOf(AccessTokenUnavailableException.class);
    }

    @Test
    @ExtendWith(OutputCaptureExtension.class)
    public void shouldAcceptHttp204WhenRevokingRefreshToken(CapturedOutput output) throws Exception {
        respond(HttpStatus.OK, ISSUE_RESPONSE);
        // i.e. Keycloak
        respond(HttpStatus.NO_CONTENT, null);

        provider.getAccessToken(false);
        provider.close();

        assertThat(provider.getRefreshToken()).isNull();
        assertThat(output.getAll()).doesNotContain("response code 204");

        assertThat(requests).containsExactly(URI.create(ISSUE_URL), URI.create(REVOKE_URL)).inOrder();
    }

    @Test
    public void shouldAuthenticateRefreshAndRevokeRequestsUsingAuthorizationHeader() throws Exception {
        String authorization = AuthorizationHeaderUtil.createHeader("myClientId", "mySecret");

        try (MockWebServer server = new MockWebServer()) {
            WebClientStatefulUrlAccessTokenProvider provider = newProvider(server, Map.of("grant_type", "client_credentials", "audience", "myAudience"), Map.of(HttpHeaders.AUTHORIZATION, authorization));

            assertThat(provider.getAccessToken(false).getValue()).isEqualTo("x.y.z");
            assertThat(provider.getAccessToken(true).getValue()).isEqualTo("a1.b1.c1");
            provider.close();

            RecordedRequest issue = server.takeRequest();
            assertThat(issue.getPath()).isEqualTo("/token");
            assertThat(issue.getHeader(HttpHeaders.AUTHORIZATION)).isEqualTo(authorization);

            RecordedRequest refresh = server.takeRequest();
            assertThat(refresh.getPath()).isEqualTo("/refresh");
            assertThat(refresh.getHeader(HttpHeaders.AUTHORIZATION)).isEqualTo(authorization);
            assertThat(refresh.getBody().readUtf8()).isEqualTo("grant_type=refresh_token&refresh_token=a.b.c");

            RecordedRequest revoke = server.takeRequest();
            assertThat(revoke.getPath()).isEqualTo("/logout");
            assertThat(revoke.getHeader(HttpHeaders.AUTHORIZATION)).isEqualTo(authorization);
            assertThat(revoke.getBody().readUtf8()).isEqualTo("refresh_token=a2.b2.c2");
        }
    }

    @Test
    public void shouldAuthenticateRefreshAndRevokeRequestsUsingBodyParameters() throws Exception {
        Map<String, Object> parameters = new HashMap<>();
        parameters.put("grant_type", "client_credentials");
        parameters.put("audience", "myAudience");
        parameters.put("client_id", "myClientId");
        parameters.put("client_secret", "mySecret");

        try (MockWebServer server = new MockWebServer()) {
            WebClientStatefulUrlAccessTokenProvider provider = newProvider(server, parameters, Collections.emptyMap());

            assertThat(provider.getAccessToken(false).getValue()).isEqualTo("x.y.z");
            assertThat(provider.getAccessToken(true).getValue()).isEqualTo("a1.b1.c1");
            provider.close();

            server.takeRequest(); // issue

            RecordedRequest refresh = server.takeRequest();
            assertThat(refresh.getPath()).isEqualTo("/refresh");
            assertThat(refresh.getHeader(HttpHeaders.AUTHORIZATION)).isNull();
            assertThat(refresh.getBody().readUtf8()).isEqualTo("grant_type=refresh_token&refresh_token=a.b.c&client_id=myClientId&client_secret=mySecret");

            RecordedRequest revoke = server.takeRequest();
            assertThat(revoke.getPath()).isEqualTo("/logout");
            assertThat(revoke.getHeader(HttpHeaders.AUTHORIZATION)).isNull();
            assertThat(revoke.getBody().readUtf8()).isEqualTo("refresh_token=a2.b2.c2&client_id=myClientId&client_secret=mySecret");
        }
    }

    private static WebClientStatefulUrlAccessTokenProvider newProvider(MockWebServer server, Map<String, Object> parameters, Map<String, Object> headers) {
        server.enqueue(new MockResponse().setHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE).setBody(ISSUE_RESPONSE));
        server.enqueue(new MockResponse().setHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE).setBody(REISSUE_RESPONSE));
        server.enqueue(new MockResponse().setResponseCode(204));

        return new WebClientStatefulUrlAccessTokenProvider(WebClient.create(), server.url("/token").url(), parameters, headers, server.url("/refresh").url(), server.url("/logout").url());
    }
}
