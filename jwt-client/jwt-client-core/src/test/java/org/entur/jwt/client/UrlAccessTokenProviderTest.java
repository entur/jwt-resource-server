package org.entur.jwt.client;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;

import java.io.ByteArrayInputStream;
import java.net.MalformedURLException;
import java.net.SocketTimeoutException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.concurrent.TimeUnit;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.when;

public class UrlAccessTokenProviderTest extends AbstractUrlAccessTokenProviderTest {

    @Test
    public void shouldFailHealthCheck() throws Exception {
        try (UrlAccessTokenProvider urlProvider = new UrlAccessTokenProvider(new URL("https://localhost"), Collections.emptyMap(), Collections.emptyMap(), 15000, 15000)) {

            assertThrows(AccessTokenHealthNotSupportedException.class, () -> {
                urlProvider.getHealth(false);
            });
        }
    }

    private AccessTokenProvider providerForResource(String resource) throws Exception {
        when(urlConnection.getInputStream()).thenReturn(getClass().getResourceAsStream(resource));

        return new DefaultAccessTokenHealthProvider(new UrlAccessTokenProvider(new URL("mock://localhost"), Collections.emptyMap(), Collections.emptyMap(), 15000, 15000) {
            @Override
            protected long nanoTime() {
                return 0L;
            }
        });
    }

    @Test
    public void shouldReturnAccessToken() throws Exception {
        AccessTokenProvider provider = providerForResource("/auth0ClientCredentialsResponse.json");

        AccessToken accessToken = provider.getAccessToken(false);
        assertNotNull(accessToken);
        assertNotNull(accessToken.getType());
        assertNotNull(accessToken.getValue());
        assertTrue(accessToken.isValid(0));
    }

    @Test
    public void shouldFailToLoadSingleWhenUrlHasNothing() throws Exception {

        AccessTokenProvider provider = providerForResource("/");

        assertThrows(AccessTokenException.class, () -> {
            provider.getAccessToken(false);
        });
    }

    @Test
    public void shouldThrowAccessTokenExceptionOnUnknownStatusCode() throws Exception {
        AccessTokenProvider provider = providerForResource("/auth0ClientCredentialsResponse.json");
        when(urlConnection.getResponseCode()).thenReturn(999);
        assertThrows(AccessTokenException.class, () -> {
            provider.getAccessToken(false);
        });
    }

    @Test
    public void shouldThrowUnavailableAccessTokenExceptionOnHttp503() throws Exception {
        AccessTokenProvider provider = providerForResource("/auth0ClientCredentialsResponse.json");
        when(urlConnection.getResponseCode()).thenReturn(503);
        assertThrows(AccessTokenUnavailableException.class, () -> {
            provider.getAccessToken(false);
        });
    }

    @Test
    public void shouldThrowAccessTokenUnavailableExceptionOnHttp429() throws Exception {
        AccessTokenProvider provider = providerForResource("/auth0ClientCredentialsResponse.json");
        when(urlConnection.getResponseCode()).thenReturn(429);
        assertThrows(AccessTokenUnavailableException.class, () -> {
            provider.getAccessToken(false);
        });
    }

    @ParameterizedTest
    @ValueSource(ints = {429, 503})
    public void shouldHonorRetryAfterWithoutIssuingAnImmediateRetry(int status) throws Exception {
        AccessTokenProvider provider = new RetryingAccessTokenProvider(providerForResource("/auth0ClientCredentialsResponse.json")) {
            @Override
            protected long nanoTime() {
                return 0L;
            }
        };
        when(urlConnection.getResponseCode()).thenReturn(status);
        when(urlConnection.getHeaderField("Retry-After")).thenReturn("120");
        AccessTokenRetryAfterException failure = assertThrows(AccessTokenRetryAfterException.class,
                () -> provider.getAccessToken(false));
        assertThat(failure.getRetryAfterDeadlineNanos()).isEqualTo(TimeUnit.SECONDS.toNanos(120));
        assertThat(failure.isRequestAttempted()).isTrue();
        AccessTokenRetryAfterException rejected = assertThrows(AccessTokenRetryAfterException.class,
                () -> provider.getAccessToken(true));
        assertThat(rejected.getRetryAfterDeadlineNanos()).isEqualTo(failure.getRetryAfterDeadlineNanos());
        assertThat(rejected.isRequestAttempted()).isFalse();
        verify(urlConnection, times(1)).getResponseCode();
        verify(urlConnection, times(1)).disconnect();
    }

    @Test
    public void shouldDisconnectAfterAccessToken() throws Exception {
        AccessTokenProvider provider = providerForResource("/auth0ClientCredentialsResponse.json");

        assertNotNull(provider.getAccessToken(false));

        verify(urlConnection).disconnect();
    }

    @Test
    public void shouldDisconnectOnHttp401() throws Exception {
        AccessTokenProvider provider = providerForResource("/auth0ClientCredentialsResponse.json");
        when(urlConnection.getResponseCode()).thenReturn(401);

        AccessTokenException e = assertThrows(AccessTokenException.class, () -> {
            provider.getAccessToken(false);
        });
        assertThat(e).isNotInstanceOf(AccessTokenUnavailableException.class);

        // i.e. release the error stream and the underlying socket
        verify(urlConnection).disconnect();
    }

    @Test
    public void shouldDisconnectOnHttp503() throws Exception {
        AccessTokenProvider provider = providerForResource("/auth0ClientCredentialsResponse.json");
        when(urlConnection.getResponseCode()).thenReturn(503);

        assertThrows(AccessTokenUnavailableException.class, () -> {
            provider.getAccessToken(false);
        });

        verify(urlConnection).disconnect();
    }

    @Test
    public void shouldDisconnectWhenRequestFails() throws Exception {
        AccessTokenProvider provider = providerForResource("/auth0ClientCredentialsResponse.json");
        doThrow(new SocketTimeoutException("Read timed out")).when(urlConnection).getResponseCode();

        assertThrows(AccessTokenUnavailableException.class, () -> {
            provider.getAccessToken(false);
        });

        verify(urlConnection).disconnect();
    }

    @Test
    public void shouldFailWithNegativeConnectTimeout() throws MalformedURLException {
        assertThrows(IllegalArgumentException.class, () -> {
            new UrlAccessTokenProvider(new URL("https://localhost"), Collections.emptyMap(), Collections.emptyMap(), -1, 15000);
        });
    }

    @Test
    public void shouldFailWithNegativeReadTimeout() throws MalformedURLException {
        assertThrows(IllegalArgumentException.class, () -> {
            new UrlAccessTokenProvider(new URL("https://localhost"), Collections.emptyMap(), Collections.emptyMap(), 15000, -1);
        });
    }

    @Test
    public void shouldFailWithAccessTokenUnavailableExceptionWhenUnparsableEntity() throws Exception {
        when(urlConnection.getInputStream()).thenReturn(new ByteArrayInputStream("{unaparsable}".getBytes(StandardCharsets.UTF_8)));

        try (DefaultAccessTokenHealthProvider provider = new DefaultAccessTokenHealthProvider(new UrlAccessTokenProvider(new URL("mock://localhost"), Collections.emptyMap(), Collections.emptyMap(), 15000, 15000))) {

            assertThrows(AccessTokenUnavailableException.class, () -> {
                provider.getAccessToken(false);
            });
        }
    }

    @Test
    public void shouldFailWithAccessTokenUnavailableExceptionWhenEmptyEntity() throws Exception {
        try (UrlAccessTokenProvider provider = new UrlAccessTokenProvider(mockUrl, Collections.emptyMap(), Collections.emptyMap(), 15000, 15000)) {
            // i.e. some HTTP clients return null for an empty response body
            assertThrows(AccessTokenUnavailableException.class, () -> {
                provider.validate(null);
            });
        }
    }

    @Test
    public void shouldConfigureURLConnection() throws Exception {
        when(urlConnection.getInputStream()).thenReturn(getClass().getResourceAsStream("/auth0ClientCredentialsResponse.json"));

        int connectTimeout = 10000;
        int readTimeout = 15000;

        try (DefaultAccessTokenHealthProvider urlJwkProvider = new DefaultAccessTokenHealthProvider(new UrlAccessTokenProvider(new URL("mock://localhost"), Collections.emptyMap(), Collections.emptyMap(), connectTimeout, readTimeout))) {
            AccessToken token = urlJwkProvider.getAccessToken(false);
            assertNotNull(token);

            // Request Timeout assertions
            ArgumentCaptor<Integer> connectTimeoutCaptor = ArgumentCaptor.forClass(Integer.class);
            verify(urlConnection).setConnectTimeout(connectTimeoutCaptor.capture());
            assertThat(connectTimeoutCaptor.getValue()).isEqualTo(connectTimeout);

            ArgumentCaptor<Integer> readTimeoutCaptor = ArgumentCaptor.forClass(Integer.class);
            verify(urlConnection).setReadTimeout(readTimeoutCaptor.capture());
            assertThat(readTimeoutCaptor.getValue()).isEqualTo(readTimeout);

            // Request Headers assertions
            verify(urlConnection).setRequestProperty("Accept", "application/json");
        }
    }
}
