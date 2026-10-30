package org.entur.jwt.client.spring.restclient;

import org.entur.jwt.client.AccessToken;
import org.entur.jwt.client.AccessTokenUnavailableException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;

import java.net.URL;
import java.util.Collections;
import java.util.Map;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

public class RestClientUrlAccessTokenProviderTest {

    private static final String ISSUE_URL = "https://entur.org/token";

    private static final String ISSUE_RESPONSE = "{\"access_token\":\"x.y.z\",\"expires_in\":86400,\"token_type\":\"Bearer\"}";

    private MockRestServiceServer mockServer;
    private RestClientUrlAccessTokenProvider provider;

    @BeforeEach
    public void beforeEach() throws Exception {
        RestClient.Builder builder = RestClient.builder();
        mockServer = MockRestServiceServer.bindTo(builder).build();

        provider = new RestClientUrlAccessTokenProvider(builder.build(), new URL(ISSUE_URL), Map.of("grant_type", "client_credentials"), Collections.emptyMap());
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
}
