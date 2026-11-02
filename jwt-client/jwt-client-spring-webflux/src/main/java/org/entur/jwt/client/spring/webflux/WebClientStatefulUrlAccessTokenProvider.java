package org.entur.jwt.client.spring.webflux;

import org.entur.jwt.client.AbstractStatefulUrlAccessTokenProvider;
import org.entur.jwt.client.AccessTokenException;
import org.entur.jwt.client.AccessTokenUnavailableException;
import org.entur.jwt.client.ClientCredentialsResponse;
import org.entur.jwt.client.RefreshToken;
import org.entur.jwt.client.RefreshTokenException;
import org.entur.jwt.client.UrlAccessTokenProvider;
import org.entur.jwt.client.spring.actuate.AccessTokenProviderHealthIndicator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.net.URISyntaxException;
import java.net.URL;
import java.util.Map;
import java.util.Map.Entry;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.function.BiFunction;

/**
 * WebClient access-token provider. Using {@linkplain UrlAccessTokenProvider}
 * would strictly be sufficient, but using RestTemplate is more convenient for
 * mocking.
 */

public class WebClientStatefulUrlAccessTokenProvider extends AbstractStatefulUrlAccessTokenProvider {

    protected static final Logger LOGGER = LoggerFactory.getLogger(WebClientStatefulUrlAccessTokenProvider.class);

    protected final WebClient webClient;

    public WebClientStatefulUrlAccessTokenProvider(WebClient webClient, URL issueUrl, Map<String, Object> parameters, Map<String, Object> headers, URL refreshUrl, URL revokeUrl) {
        super(issueUrl, parameters, headers, refreshUrl, revokeUrl);
        this.webClient = webClient;
    }

    protected ClientCredentialsResponse getToken() throws AccessTokenException {
        CompletableFuture<ClientCredentialsResponse> future = request(issueUrl, issueBody, issueHeaders).toFuture();
        try {
            ClientCredentialsResponse clientCredentialsResponse = future.get();
            validate(clientCredentialsResponse);
            return clientCredentialsResponse;
        } catch (InterruptedException e) {
            // cancel the request, so that it does not continue after the exclusive lock above is released
            future.cancel(true);
            Thread.currentThread().interrupt();
            throw new AccessTokenUnavailableException(e);
        } catch (ExecutionException e) {
            Throwable cause = e.getCause();
            if(cause instanceof AccessTokenException a) {
                throw a;
            }
            throw new AccessTokenUnavailableException(e);
        }
    }

    protected Mono<ClientCredentialsResponse> request(URL url, byte[] body, Map<String, Object> map) {
        return request(url, body, map, (status, cause) -> new AccessTokenException("Authorization server responded with HTTP unexpected response code " + status, cause));
    }

    protected Mono<ClientCredentialsResponse> request(URL url, byte[] body, Map<String, Object> map, BiFunction<HttpStatusCode, Throwable, AccessTokenException> unexpectedResponse) {
        HttpHeaders headers = new HttpHeaders();

        for (Entry<String, Object> entry : map.entrySet()) {
            headers.set(entry.getKey(), entry.getValue().toString());
        }

        try {
            return webClient
                    .post()
                    .uri(url.toURI())
                    .accept(MediaType.APPLICATION_JSON)
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .headers(httpHeaders -> httpHeaders.addAll(headers))
                    .bodyValue(body)
                    .retrieve()
                    .onStatus(httpStatus -> httpStatus == HttpStatus.TOO_MANY_REQUESTS,
                            response -> {
                                logUnexpectedStatus(url, response.statusCode().value());
                                HttpHeaders responseHeaders = response.headers().asHttpHeaders();
                                // Headers are available now; body capture below may be cancelled.
                                AccessTokenException recorded = retryAfterException(
                                        "Authorization server responded with HTTP code 429 - too many requests.",
                                        responseHeaders::getFirst);
                                return WebClientUrlAccessTokenProvider.httpError(response, recorded);
                            }
                    )
                    .onStatus(httpStatus -> httpStatus == HttpStatus.SERVICE_UNAVAILABLE,
                            response -> {
                                logUnexpectedStatus(url, response.statusCode().value());
                                HttpHeaders responseHeaders = response.headers().asHttpHeaders();
                                AccessTokenException recorded = retryAfterException(
                                        "Authorization server responded with HTTP code 503 - service unavailable.",
                                        responseHeaders::getFirst);
                                return WebClientUrlAccessTokenProvider.httpError(response, recorded);
                            }
                    )
                    .onStatus(httpStatus -> !httpStatus.is2xxSuccessful(),
                            response -> {
                                logUnexpectedStatus(url, response.statusCode().value());
                                return WebClientUrlAccessTokenProvider.httpError(response,
                                        exception -> unexpectedResponse.apply(response.statusCode(), exception));
                            }
                    )
                    .bodyToMono(ClientCredentialsResponse.class);
        } catch (URISyntaxException e) {
            throw new IllegalArgumentException(e);
        }
    }

    private void logUnexpectedStatus(URL url, int responseCode) {
        if (!LOGGER.isInfoEnabled()) {
            return;
        }
        if (issueUrl.equals(url)) {
            LOGGER.info("Got unexpected response code {} when trying to issue token at {}", responseCode, url);
        } else {
            LOGGER.info("Got unexpected response code {} when trying to refresh token at {}", responseCode, url);
        }
    }

    @Override
    protected void close(long time) {
        RefreshToken threadSafeRefreshToken = this.refreshToken; // defensive copy
        if (threadSafeRefreshToken != null && threadSafeRefreshToken.isValid(time)) {
            this.refreshToken = null;

            try {
                byte[] revokeBody = createRevokeBody(threadSafeRefreshToken);

                HttpHeaders headers = new HttpHeaders();
                for (Entry<String, Object> entry : revokeHeaders.entrySet()) {
                    headers.set(entry.getKey(), entry.getValue().toString());
                }

                Mono<ResponseEntity<Void>> mono = webClient
                        .post()
                        .uri(revokeUrl.toURI())
                        .accept(MediaType.APPLICATION_JSON)
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .headers(httpHeaders -> httpHeaders.addAll(headers))
                        .bodyValue(revokeBody)
                        .retrieve()
                        .toBodilessEntity();

                ResponseEntity<Void> response = mono.block();

                int responseStatusCode = response.getStatusCode().value();
                if (!response.getStatusCode().is2xxSuccessful()) { // i.e. Keycloak responds with 204
                    if(LOGGER.isInfoEnabled()) LOGGER.info("Unexpected response code {} when revoking refresh token", responseStatusCode);
                }
            } catch (URISyntaxException e) {
                throw new IllegalArgumentException(e);
            } catch (Exception e) {
                if(LOGGER.isInfoEnabled()) LOGGER.info("Unable to revoke token", e);
            }
        }
    }

    protected ClientCredentialsResponse getToken(RefreshToken refreshToken) throws AccessTokenException {
        byte[] refreshBody = createRefreshBody(refreshToken);

        CompletableFuture<ClientCredentialsResponse> future = request(refreshUrl, refreshBody, refreshHeaders,
                (status, cause) -> refreshFailure(status.value(), "Authorization server responded with HTTP unexpected response code " + status + " when refreshing token", cause)).toFuture();
        try {
            ClientCredentialsResponse clientCredentialsResponse = future.get();
            validate(clientCredentialsResponse);
            return clientCredentialsResponse;
        } catch (InterruptedException e) {
            // cancel the request, so that it does not continue after the exclusive lock above is released
            future.cancel(true);
            Thread.currentThread().interrupt();
            throw new AccessTokenUnavailableException(e);
        } catch (ExecutionException e) {
            Throwable cause = e.getCause();
            if(cause instanceof AccessTokenUnavailableException a) {
                throw a;
            }
            if(cause instanceof RefreshTokenException r) {
                throw r;
            }
            if(cause instanceof AccessTokenException a) {
                // assume current session has been revoked or expired
                throw new RefreshTokenException(a.getMessage() + " when refreshing token", a);
            }
            throw new AccessTokenUnavailableException(e);
        }
    }


}
