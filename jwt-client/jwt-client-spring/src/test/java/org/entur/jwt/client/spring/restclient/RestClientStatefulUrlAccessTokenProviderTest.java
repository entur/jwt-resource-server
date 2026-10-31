package org.entur.jwt.client.spring.restclient;

import org.entur.jwt.client.AccessTokenUnavailableException;
import org.entur.jwt.client.AccessTokenRetryAfterException;
import org.entur.jwt.client.AuthorizationHeaderUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.MediaType;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.test.web.client.ResponseCreator;
import org.springframework.web.client.RestClient;

import java.net.URL;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.content;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.header;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.headerDoesNotExist;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withBadRequest;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withNoContent;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withServiceUnavailable;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withStatus;

public class RestClientStatefulUrlAccessTokenProviderTest {

    private static final String ISSUE_URL = "https://entur.org/token";
    private static final String REFRESH_URL = "https://entur.org/refresh";
    private static final String REVOKE_URL = "https://entur.org/logout";

    private static final String ISSUE_RESPONSE = "{\"access_token\":\"x.y.z\",\"expires_in\":86400,\"token_type\":\"Bearer\",\"refresh_token\":\"a.b.c\",\"refresh_expires_in\":604800}";
    private static final String REISSUE_RESPONSE = "{\"access_token\":\"a1.b1.c1\",\"expires_in\":86400,\"token_type\":\"Bearer\",\"refresh_token\":\"a2.b2.c2\",\"refresh_expires_in\":604800}";

    private MockRestServiceServer mockServer;
    private RestClient restClient;
    private RestClientStatefulUrlAccessTokenProvider provider;
    private long nowNanos;

    @BeforeEach
    public void beforeEach() throws Exception {
        RestClient.Builder builder = RestClient.builder();
        mockServer = MockRestServiceServer.bindTo(builder).build();
        restClient = builder.build();

        provider = newProvider(Map.of("grant_type", "client_credentials"), Collections.emptyMap());
    }

    private RestClientStatefulUrlAccessTokenProvider newProvider(Map<String, Object> parameters, Map<String, Object> headers) throws Exception {
        return new RestClientStatefulUrlAccessTokenProvider(restClient, new URL(ISSUE_URL), parameters, headers, new URL(REFRESH_URL), new URL(REVOKE_URL)) {
            @Override
            protected long nanoTime() {
                return nowNanos;
            }
        };
    }

    private void expect(String url, ResponseCreator responseCreator) {
        mockServer.expect(requestTo(url))
                .andExpect(method(HttpMethod.POST))
                .andRespond(responseCreator);
    }

    @Test
    public void shouldIssueNewTokenWhenRefreshTokenIsRejected() throws Exception {
        expect(ISSUE_URL, withSuccess(ISSUE_RESPONSE, MediaType.APPLICATION_JSON));
        // i.e. the session has been revoked or has expired
        expect(REFRESH_URL, withBadRequest().body("{\"error\":\"invalid_grant\"}").contentType(MediaType.APPLICATION_JSON));
        expect(ISSUE_URL, withSuccess(REISSUE_RESPONSE, MediaType.APPLICATION_JSON));

        assertThat(provider.getAccessToken(false).getValue()).isEqualTo("x.y.z");
        assertThat(provider.getRefreshToken().getValue()).isEqualTo("a.b.c");

        assertThrows(AccessTokenRetryAfterException.class, () -> provider.getAccessToken(true));
        assertThat(provider.getRefreshToken()).isNull();
        nowNanos += TimeUnit.SECONDS.toNanos(15);
        assertThat(provider.getAccessToken(true).getValue()).isEqualTo("a1.b1.c1");
        assertThat(provider.getRefreshToken().getValue()).isEqualTo("a2.b2.c2");

        mockServer.verify();
    }

    @Test
    public void shouldNotIssueNewTokenWhenRefreshIsTemporarilyUnavailable() throws Exception {
        expect(ISSUE_URL, withSuccess(ISSUE_RESPONSE, MediaType.APPLICATION_JSON));
        expect(REFRESH_URL, withServiceUnavailable());

        provider.getAccessToken(false);

        assertThrows(AccessTokenUnavailableException.class, () -> {
            provider.getAccessToken(true);
        });
        // keep the session for the next attempt
        assertThat(provider.getRefreshToken().getValue()).isEqualTo("a.b.c");

        mockServer.verify();
    }

    @ParameterizedTest
    @CsvSource({"429,false", "503,false", "429,true", "503,true"})
    public void shouldHonorRetryAfterForIssueAndRefresh(int status, boolean refreshing) throws Exception {
        if (refreshing) {
            expect(ISSUE_URL, withSuccess(ISSUE_RESPONSE, MediaType.APPLICATION_JSON));
        }
        expect(refreshing ? REFRESH_URL : ISSUE_URL, withStatus(HttpStatusCode.valueOf(status)).header("Retry-After", "120"));
        expect(refreshing ? REFRESH_URL : ISSUE_URL, withSuccess(REISSUE_RESPONSE, MediaType.APPLICATION_JSON));
        if (refreshing) {
            provider.getAccessToken(false);
        }
        var original = provider.getRefreshToken();
        AccessTokenRetryAfterException failure = assertThrows(AccessTokenRetryAfterException.class,
                () -> provider.getAccessToken(false));
        assertThat(failure.getRetryAfterDeadlineNanos() - nowNanos).isEqualTo(TimeUnit.SECONDS.toNanos(120));
        assertThat(failure.getHeaders()).containsExactly("Retry-After", "120");
        assertThrows(AccessTokenRetryAfterException.class, () -> provider.getAccessToken(true));
        assertThat(provider.getRefreshToken()).isSameInstanceAs(original);
        nowNanos = TimeUnit.SECONDS.toNanos(15);
        assertThrows(AccessTokenRetryAfterException.class, () -> provider.getAccessToken(false));
        nowNanos = TimeUnit.SECONDS.toNanos(120);
        assertThat(provider.getAccessToken(false).getValue()).isEqualTo("a1.b1.c1");
        mockServer.verify();
    }

    @Test
    public void shouldAuthenticateRefreshAndRevokeRequestsUsingAuthorizationHeader() throws Exception {
        String authorization = AuthorizationHeaderUtil.createHeader("myClientId", "mySecret");

        provider = newProvider(Map.of("grant_type", "client_credentials", "audience", "myAudience"), Map.of(HttpHeaders.AUTHORIZATION, authorization));

        mockServer.expect(requestTo(ISSUE_URL))
                .andExpect(method(HttpMethod.POST))
                .andExpect(header(HttpHeaders.AUTHORIZATION, authorization))
                .andRespond(withSuccess(ISSUE_RESPONSE, MediaType.APPLICATION_JSON));
        mockServer.expect(requestTo(REFRESH_URL))
                .andExpect(method(HttpMethod.POST))
                .andExpect(header(HttpHeaders.AUTHORIZATION, authorization))
                .andExpect(content().string("grant_type=refresh_token&refresh_token=a.b.c"))
                .andRespond(withSuccess(REISSUE_RESPONSE, MediaType.APPLICATION_JSON));
        mockServer.expect(requestTo(REVOKE_URL))
                .andExpect(method(HttpMethod.POST))
                .andExpect(header(HttpHeaders.AUTHORIZATION, authorization))
                .andExpect(content().string("refresh_token=a2.b2.c2"))
                .andRespond(withNoContent());

        assertThat(provider.getAccessToken(false).getValue()).isEqualTo("x.y.z");
        assertThat(provider.getAccessToken(true).getValue()).isEqualTo("a1.b1.c1");
        provider.close();

        mockServer.verify();
    }

    @Test
    public void shouldAuthenticateRefreshAndRevokeRequestsUsingBodyParameters() throws Exception {
        Map<String, Object> parameters = new HashMap<>();
        parameters.put("grant_type", "client_credentials");
        parameters.put("audience", "myAudience");
        parameters.put("client_id", "myClientId");
        parameters.put("client_secret", "mySecret");

        provider = newProvider(parameters, Collections.emptyMap());

        mockServer.expect(requestTo(ISSUE_URL))
                .andExpect(method(HttpMethod.POST))
                .andRespond(withSuccess(ISSUE_RESPONSE, MediaType.APPLICATION_JSON));
        mockServer.expect(requestTo(REFRESH_URL))
                .andExpect(method(HttpMethod.POST))
                .andExpect(headerDoesNotExist(HttpHeaders.AUTHORIZATION))
                .andExpect(content().string("grant_type=refresh_token&refresh_token=a.b.c&client_id=myClientId&client_secret=mySecret"))
                .andRespond(withSuccess(REISSUE_RESPONSE, MediaType.APPLICATION_JSON));
        mockServer.expect(requestTo(REVOKE_URL))
                .andExpect(method(HttpMethod.POST))
                .andExpect(headerDoesNotExist(HttpHeaders.AUTHORIZATION))
                .andExpect(content().string("refresh_token=a2.b2.c2&client_id=myClientId&client_secret=mySecret"))
                .andRespond(withNoContent());

        assertThat(provider.getAccessToken(false).getValue()).isEqualTo("x.y.z");
        assertThat(provider.getAccessToken(true).getValue()).isEqualTo("a1.b1.c1");
        provider.close();

        mockServer.verify();
    }
}
