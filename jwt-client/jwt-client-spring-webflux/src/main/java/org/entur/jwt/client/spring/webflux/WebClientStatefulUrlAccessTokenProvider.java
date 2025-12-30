package org.entur.jwt.client.spring.webflux;

import org.entur.jwt.client.AbstractStatefulUrlAccessTokenProvider;
import org.entur.jwt.client.AccessTokenException;
import org.entur.jwt.client.AccessTokenUnavailableException;
import org.entur.jwt.client.ClientCredentialsResponse;
import org.entur.jwt.client.RefreshToken;
import org.entur.jwt.client.UrlAccessTokenProvider;
import org.entur.jwt.client.spring.actuate.AccessTokenProviderHealthIndicator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.net.URISyntaxException;
import java.net.URL;
import java.util.Collections;
import java.util.Map;
import java.util.Map.Entry;
import java.util.concurrent.ExecutionException;

/**
 * WebClient access-token provider. Using {@linkplain UrlAccessTokenProvider}
 * would strictly be sufficient, but using RestTemplate is more convenient for
 * mocking.
 */

public class WebClientStatefulUrlAccessTokenProvider extends AbstractStatefulUrlAccessTokenProvider {

    protected static final Logger logger = LoggerFactory.getLogger(AccessTokenProviderHealthIndicator.class);

    protected final WebClient webClient;

    public WebClientStatefulUrlAccessTokenProvider(WebClient webClient, URL issueUrl, Map<String, Object> parameters, Map<String, Object> headers, URL refreshUrl, URL revokeUrl) {
        super(issueUrl, parameters, headers, refreshUrl, revokeUrl);
        this.webClient = webClient;
    }

    protected ClientCredentialsResponse getToken() throws AccessTokenException {
        try {
            Mono<ClientCredentialsResponse> response = request(issueUrl, issueBody, issueHeaders);

            ClientCredentialsResponse clientCredentialsResponse = response.toFuture().get();
            validate(clientCredentialsResponse);
            return clientCredentialsResponse;
        } catch (InterruptedException e) {
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
                            response -> Mono.error(new AccessTokenUnavailableException("Authorization server responded with HTTP code 429 - too many requests."))
                    )
                    .onStatus(httpStatus -> httpStatus == HttpStatus.SERVICE_UNAVAILABLE,
                            response -> Mono.error(new AccessTokenUnavailableException("Authorization server responded with HTTP code 503 - service unavailable."))
                    )
                    .onStatus(httpStatus -> !httpStatus.is2xxSuccessful(),
                            response -> Mono.error(new AccessTokenException("Authorization server responded with HTTP unexpected response code " + response.statusCode()))
                    )
                    .bodyToMono(ClientCredentialsResponse.class);
        } catch (URISyntaxException e) {
            throw new IllegalArgumentException(e);
        }
    }

    protected void close(long time) {
        RefreshToken threadSafeRefreshToken = this.refreshToken; // defensive copy
        if (threadSafeRefreshToken != null && threadSafeRefreshToken.isValid(time)) {
            this.refreshToken = null;

            try {
                byte[] revokeBody = createRevokeBody(threadSafeRefreshToken);

                Mono<ResponseEntity<Void>> mono = webClient
                        .post()
                        .uri(revokeUrl.toURI())
                        .accept(MediaType.APPLICATION_JSON)
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .bodyValue(revokeBody)
                        .retrieve()
                        .toBodilessEntity();

                ResponseEntity<Void> response = mono.block();

                int responseStatusCode = response.getStatusCode().value();
                if (responseStatusCode != 200) {
                    logger.info("Unexpected response code {} when revoking refresh token", responseStatusCode);
                }
            } catch (URISyntaxException e) {
                throw new IllegalArgumentException(e);
            } catch (Exception e) {
                logger.info("Unable to revoke token", e);
            }
        }
    }

    protected ClientCredentialsResponse getToken(RefreshToken refreshToken) throws AccessTokenException {
        byte[] refreshBody = createRefreshBody(refreshToken);

        try {
            Mono<ClientCredentialsResponse> response = request(refreshUrl, refreshBody, Collections.emptyMap());

            ClientCredentialsResponse clientCredentialsResponse = response.toFuture().get();
            validate(clientCredentialsResponse);
            return clientCredentialsResponse;
        } catch (InterruptedException e) {
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


}
