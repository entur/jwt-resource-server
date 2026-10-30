package org.entur.jwt.client.spring.resttemplate;

import org.entur.jwt.client.AccessTokenException;
import org.entur.jwt.client.AccessTokenUnavailableException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.test.web.client.ResponseCreator;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;
import java.net.URL;
import java.util.Collections;
import java.util.Map;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withBadRequest;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withException;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withServiceUnavailable;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withUnauthorizedRequest;

public class RestTemplateStatefulUrlAccessTokenProviderTest {

    private static final String ISSUE_URL = "https://entur.org/token";
    private static final String REFRESH_URL = "https://entur.org/refresh";
    private static final String REVOKE_URL = "https://entur.org/logout";

    private static final String ISSUE_RESPONSE = "{\"access_token\":\"x.y.z\",\"expires_in\":86400,\"token_type\":\"Bearer\",\"refresh_token\":\"a.b.c\",\"refresh_expires_in\":604800}";
    private static final String REISSUE_RESPONSE = "{\"access_token\":\"a1.b1.c1\",\"expires_in\":86400,\"token_type\":\"Bearer\",\"refresh_token\":\"a2.b2.c2\",\"refresh_expires_in\":604800}";

    private MockRestServiceServer mockServer;
    private RestTemplateStatefulUrlAccessTokenProvider provider;

    @BeforeEach
    public void beforeEach() throws Exception {
        RestTemplate restTemplate = new RestTemplate();
        mockServer = MockRestServiceServer.bindTo(restTemplate).build();

        provider = new RestTemplateStatefulUrlAccessTokenProvider(restTemplate, new URL(ISSUE_URL), Map.of("grant_type", "client_credentials"), Collections.emptyMap(), new URL(REFRESH_URL), new URL(REVOKE_URL));
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

    @Test
    public void shouldThrowAccessTokenExceptionWhenIssueRequestIsRejected() {
        expect(ISSUE_URL, withUnauthorizedRequest());

        AccessTokenException e = assertThrows(AccessTokenException.class, () -> {
            provider.getAccessToken(false);
        });
        assertThat(e).isNotInstanceOf(AccessTokenUnavailableException.class);
        assertThat(e).hasMessageThat().contains("401");

        mockServer.verify();
    }

    @Test
    public void shouldThrowAccessTokenUnavailableExceptionWhenIssueIsTemporarilyUnavailable() {
        expect(ISSUE_URL, withServiceUnavailable());

        assertThrows(AccessTokenUnavailableException.class, () -> {
            provider.getAccessToken(false);
        });

        mockServer.verify();
    }

    @Test
    public void shouldThrowAccessTokenUnavailableExceptionWhenIssueRequestFails() {
        expect(ISSUE_URL, withException(new IOException("Connection refused")));

        assertThrows(AccessTokenUnavailableException.class, () -> {
            provider.getAccessToken(false);
        });

        mockServer.verify();
    }
}
