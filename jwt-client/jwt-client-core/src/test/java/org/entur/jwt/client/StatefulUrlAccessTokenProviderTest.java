package org.entur.jwt.client;

import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class StatefulUrlAccessTokenProviderTest extends AbstractUrlAccessTokenProviderTest {

    @Test
    public void shouldFailHealthCheck() throws Exception {
        try (StatefulUrlAccessTokenProvider urlProvider = new StatefulUrlAccessTokenProvider(new URL("https://localhost"), Collections.emptyMap(), Collections.emptyMap(), 15000, 15000, mockUrl, mockUrl)) {

            assertThrows(AccessTokenHealthNotSupportedException.class, () -> {
                urlProvider.getHealth(false);
            });
        }
    }

    private StatefulUrlAccessTokenProvider providerForResource(String resource) throws Exception {
        when(urlConnection.getInputStream()).thenReturn(getClass().getResourceAsStream(resource));

        Map<String, Object> headers = new HashMap<>();
        headers.put("Authorization", "abcdef");

        Map<String, Object> parameters = new HashMap<>();
        parameters.put(AbstractClientCredentialsBuilder.KEY_GRANT_TYPE, AbstractClientCredentialsBuilder.KEY_CLIENT_CREDENTIALS);

        return new StatefulUrlAccessTokenProvider(mockUrl, parameters, headers, 15000, 15000, mockUrl, mockUrl);
    }

    @Test
    public void shouldReturnAccessToken() throws Exception {
        AccessTokenProvider provider = providerForResource("/keycloakClientCredentialsResponse.json");
        assertThat(provider.getAccessToken(false)).isNotNull();
    }

    @Test
    public void shouldUseRefreshTokenToRefreshExpiredAccessToken() throws Exception {
        StatefulUrlAccessTokenProvider provider = providerForResource("/keycloakClientCredentialsResponse.json");
        AccessToken accessToken = provider.getAccessToken(false);
        assertThat(accessToken).isNotNull();

        ByteArrayOutputStream output = new ByteArrayOutputStream();
        when(urlConnection.getInputStream()).thenReturn(getClass().getResourceAsStream("/keycloakClientCredentialsResponse.json"));
        when(urlConnection.getOutputStream()).thenReturn(output);

        AccessToken refreshedAccessToken = provider.getAccessToken(accessToken.getExpires() + 1);
        assertThat(refreshedAccessToken).isNotNull();
        assertThat(refreshedAccessToken).isNotSameInstanceAs(accessToken);

        String body = output.toString();
        assertThat(body).contains(StatefulUrlAccessTokenProvider.KEY_REFRESH_TOKEN);
    }

    @Test
    public void shouldUseClientCredentialsToRefreshExpiredRefreshToken() throws Exception {
        StatefulUrlAccessTokenProvider provider = providerForResource("/keycloakClientCredentialsResponse.json");
        AccessToken accessToken = provider.getAccessToken(false);
        assertThat(accessToken).isNotNull();

        ByteArrayOutputStream output = new ByteArrayOutputStream();
        when(urlConnection.getInputStream()).thenReturn(getClass().getResourceAsStream("/keycloakClientCredentialsResponse.json"));
        when(urlConnection.getOutputStream()).thenReturn(output);

        RefreshToken refreshToken = provider.getRefreshToken();

        AccessToken refreshedAccessToken = provider.getAccessToken(refreshToken.getExpires() + 1);
        assertThat(refreshedAccessToken).isNotNull();
        assertThat(refreshedAccessToken).isNotSameInstanceAs(accessToken);

        String body = output.toString();
        assertThat(body).contains(AbstractClientCredentialsBuilder.KEY_CLIENT_CREDENTIALS);
    }

    @Test
    public void shouldFailToLoadSingleWhenUrlHasNothing() throws Exception {

        AccessTokenProvider provider = providerForResource("/");

        assertThrows(AccessTokenException.class, () -> {
            provider.getAccessToken(false);
        });
    }

    @Test
    public void shouldFailWithNegativeConnectTimeout() throws MalformedURLException {
        assertThrows(IllegalArgumentException.class, () -> {
            new StatefulUrlAccessTokenProvider(new URL("https://localhost"), Collections.emptyMap(), Collections.emptyMap(), -1, 15000, mockUrl, mockUrl);
        });
    }

    @Test
    public void shouldFailWithNegativeReadTimeout() throws MalformedURLException {
        assertThrows(IllegalArgumentException.class, () -> {
            new StatefulUrlAccessTokenProvider(new URL("https://localhost"), Collections.emptyMap(), Collections.emptyMap(), 15000, -1, mockUrl, mockUrl);
        });
    }

    @Test
    public void shouldFailWithAccessTokenUnavailableExceptionWhenUnparsableEntity() throws Exception {
        when(urlConnection.getInputStream()).thenReturn(new ByteArrayInputStream("{unaparsable}".getBytes(StandardCharsets.UTF_8)));

        try (DefaultAccessTokenHealthProvider provider = new DefaultAccessTokenHealthProvider(new StatefulUrlAccessTokenProvider(mockUrl, Collections.emptyMap(), Collections.emptyMap(), 15000, 15000, mockUrl, mockUrl))) {

            assertThrows(AccessTokenUnavailableException.class, () -> {
                provider.getAccessToken(false);
            });
        }
    }

    @Test
    public void shouldConfigureURLConnection() throws Exception {
        when(urlConnection.getInputStream()).thenReturn(getClass().getResourceAsStream("/keycloakClientCredentialsResponse.json"));

        int connectTimeout = 10000;
        int readTimeout = 15000;

        try (DefaultAccessTokenHealthProvider urlJwkProvider = new DefaultAccessTokenHealthProvider(
                new StatefulUrlAccessTokenProvider(mockUrl, Collections.emptyMap(), Collections.emptyMap(), connectTimeout, readTimeout, mockUrl, mockUrl))) {
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

    @Test
    public void shouldThrowAccessTokenExceptionOnUnknownStatusCode() throws Exception {
        StatefulUrlAccessTokenProvider provider = providerForResource("/keycloakClientCredentialsResponse.json");
        AccessToken accessToken = provider.getAccessToken(false);
        assertThat(accessToken).isNotNull();

        ByteArrayOutputStream output = new ByteArrayOutputStream();
        when(urlConnection.getInputStream()).thenReturn(getClass().getResourceAsStream("/keycloakClientCredentialsResponse.json"));
        when(urlConnection.getOutputStream()).thenReturn(output);
        when(urlConnection.getResponseCode()).thenReturn(999);

        assertThrows(AccessTokenException.class, () -> {
            provider.getAccessToken(accessToken.getExpires() + 1);
        });
    }

    @Test
    public void shouldThrowUnavailableAccessTokenExceptionOnHttp503() throws Exception {
        StatefulUrlAccessTokenProvider provider = providerForResource("/keycloakClientCredentialsResponse.json");
        AccessToken accessToken = provider.getAccessToken(false);
        assertThat(accessToken).isNotNull();

        ByteArrayOutputStream output = new ByteArrayOutputStream();
        when(urlConnection.getInputStream()).thenReturn(getClass().getResourceAsStream("/keycloakClientCredentialsResponse.json"));
        when(urlConnection.getOutputStream()).thenReturn(output);
        when(urlConnection.getResponseCode()).thenReturn(503);

        assertThrows(AccessTokenUnavailableException.class, () -> {
            provider.getAccessToken(accessToken.getExpires() + 1);
        });
    }

    @Test
    public void shouldThrowAccessTokenUnavailableExceptionOnHttp429() throws Exception {
        StatefulUrlAccessTokenProvider provider = providerForResource("/keycloakClientCredentialsResponse.json");
        AccessToken accessToken = provider.getAccessToken(false);
        assertThat(accessToken).isNotNull();

        ByteArrayOutputStream output = new ByteArrayOutputStream();
        when(urlConnection.getInputStream()).thenReturn(getClass().getResourceAsStream("/keycloakClientCredentialsResponse.json"));
        when(urlConnection.getOutputStream()).thenReturn(output);
        when(urlConnection.getResponseCode()).thenReturn(429);

        assertThrows(AccessTokenUnavailableException.class, () -> {
            provider.getAccessToken(accessToken.getExpires() + 1);
        });
    }

    @Test
    public void shouldWaitAndConsumeRotatedRefreshTokenWhenRequestsOverlap() throws Exception {
        CountDownLatch thread1InGetTokenLatch = new CountDownLatch(1);
        CountDownLatch thread1CanFinishLatch = new CountDownLatch(1);
        List<String> consumedRefreshTokens = Collections.synchronizedList(new ArrayList<>());

        StatefulUrlAccessTokenProvider provider = new StatefulUrlAccessTokenProvider(
                mockUrl, Collections.emptyMap(), Collections.emptyMap(), 15000, 15000, mockUrl, mockUrl, 5000
        ) {
            @Override
            protected ClientCredentialsResponse getToken(RefreshToken response) throws AccessTokenException {
                consumedRefreshTokens.add(response.getValue());
                if ("rt-1".equals(response.getValue())) {
                    thread1InGetTokenLatch.countDown();
                    try {
                        thread1CanFinishLatch.await(5, TimeUnit.SECONDS);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    }
                    ClientCredentialsResponse res = mock(ClientCredentialsResponse.class);
                    when(res.getAccessToken()).thenReturn("at-2");
                    when(res.getTokenType()).thenReturn("Bearer");
                    when(res.getExpiresIn()).thenReturn(3600L);
                    when(res.getRefreshToken()).thenReturn("rt-2");
                    when(res.getRefreshExpiresIn()).thenReturn(3600L);
                    return res;
                } else if ("rt-2".equals(response.getValue())) {
                    ClientCredentialsResponse res = mock(ClientCredentialsResponse.class);
                    when(res.getAccessToken()).thenReturn("at-3");
                    when(res.getTokenType()).thenReturn("Bearer");
                    when(res.getExpiresIn()).thenReturn(3600L);
                    when(res.getRefreshToken()).thenReturn("rt-3");
                    when(res.getRefreshExpiresIn()).thenReturn(3600L);
                    return res;
                }
                return super.getToken(response);
            }
        };

        provider.refreshToken = new RefreshToken("rt-1", System.currentTimeMillis() + 100000);

        ExecutorService executor = Executors.newFixedThreadPool(2);
        try {
            long now = System.currentTimeMillis();

            Future<AccessToken> future1 = executor.submit(() -> provider.getAccessToken(now));

            assertThat(thread1InGetTokenLatch.await(5, TimeUnit.SECONDS)).isTrue();

            Future<AccessToken> future2 = executor.submit(() -> provider.getAccessToken(now));

            Thread.sleep(100);

            thread1CanFinishLatch.countDown();

            AccessToken token1 = future1.get(5, TimeUnit.SECONDS);
            AccessToken token2 = future2.get(5, TimeUnit.SECONDS);

            assertThat(token1.getValue()).isEqualTo("at-2");
            assertThat(token2.getValue()).isEqualTo("at-3");

            assertThat(consumedRefreshTokens).containsExactly("rt-1", "rt-2").inOrder();
        } finally {
            executor.shutdownNow();
        }
    }

    @Test
    public void shouldThrowAccessTokenUnavailableExceptionOnLockTimeout() throws Exception {
        CountDownLatch thread1InLockLatch = new CountDownLatch(1);
        CountDownLatch thread1CanFinishLatch = new CountDownLatch(1);

        StatefulUrlAccessTokenProvider provider = new StatefulUrlAccessTokenProvider(
                mockUrl, Collections.emptyMap(), Collections.emptyMap(), 15000, 15000, mockUrl, mockUrl, 100
        ) {
            @Override
            protected ClientCredentialsResponse getToken(RefreshToken response) throws AccessTokenException {
                thread1InLockLatch.countDown();
                try {
                    thread1CanFinishLatch.await(5, TimeUnit.SECONDS);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
                ClientCredentialsResponse res = mock(ClientCredentialsResponse.class);
                when(res.getAccessToken()).thenReturn("at-1");
                when(res.getTokenType()).thenReturn("Bearer");
                when(res.getExpiresIn()).thenReturn(3600L);
                return res;
            }
        };

        provider.refreshToken = new RefreshToken("rt-1", System.currentTimeMillis() + 100000);

        ExecutorService executor = Executors.newFixedThreadPool(2);
        try {
            long now = System.currentTimeMillis();

            Future<AccessToken> future1 = executor.submit(() -> provider.getAccessToken(now));

            assertThat(thread1InLockLatch.await(5, TimeUnit.SECONDS)).isTrue();

            Future<AccessToken> future2 = executor.submit(() -> provider.getAccessToken(now));

            ExecutionException exception = assertThrows(ExecutionException.class, () -> future2.get(5, TimeUnit.SECONDS));
            assertThat(exception.getCause()).isInstanceOf(AccessTokenUnavailableException.class);
            assertThat(exception.getCause().getMessage()).contains("Timeout while waiting to refresh access token");

            thread1CanFinishLatch.countDown();
            future1.get(5, TimeUnit.SECONDS);
        } finally {
            executor.shutdownNow();
        }
    }

}
