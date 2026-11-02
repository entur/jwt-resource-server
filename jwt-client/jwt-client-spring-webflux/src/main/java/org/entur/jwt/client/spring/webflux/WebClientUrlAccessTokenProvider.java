package org.entur.jwt.client.spring.webflux;

import org.entur.jwt.client.AbstractUrlAccessTokenProvider;
import org.entur.jwt.client.AccessTokenException;
import org.entur.jwt.client.AccessTokenUnavailableException;
import org.entur.jwt.client.ClientCredentialsResponse;
import org.entur.jwt.client.UrlAccessTokenProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import reactor.core.publisher.Mono;

import java.net.URISyntaxException;
import java.net.URL;
import java.util.Map;
import java.util.Map.Entry;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.function.Function;

/**
 * WebClient access-token provider. Using {@linkplain UrlAccessTokenProvider}
 * would strictly be sufficient, but using WebClient is more convenient for
 * mocking.
 */

public class WebClientUrlAccessTokenProvider extends AbstractUrlAccessTokenProvider {

    protected final WebClient webClient;

    protected static final Logger logger = LoggerFactory.getLogger(WebClientUrlAccessTokenProvider.class);

    /**
     * Read the error response into a {@link WebClientResponseException} and attach it as the cause.
     */
    protected static Mono<Throwable> httpError(ClientResponse response, Function<WebClientResponseException, AccessTokenException> failure) {
        return response.createException().flatMap(exception -> Mono.error(failure.apply(exception)));
    }

    public WebClientUrlAccessTokenProvider(WebClient webClient, URL issueUrl, Map<String, Object> parameters, Map<String, Object> headers) {
        super(issueUrl, parameters, headers);

        this.webClient = webClient;
    }

    @Override
    protected ClientCredentialsResponse getToken() throws AccessTokenException {
        CompletableFuture<ClientCredentialsResponse> future;
        try {
            Mono<ClientCredentialsResponse> mono = webClient
                .post()
                .uri(issueUrl.toURI())
                .accept(MediaType.APPLICATION_JSON)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .headers(httpHeaders -> {
                    for (Entry<String, Object> entry : issueHeaders.entrySet()) {
                        httpHeaders.set(entry.getKey(), entry.getValue().toString());
                    }
                })
                .bodyValue(issueBody)
                .retrieve()
                .onStatus(httpStatus -> httpStatus == HttpStatus.TOO_MANY_REQUESTS,
                        response -> {
                            HttpHeaders headers = response.headers().asHttpHeaders();
                            return httpError(response, exception -> retryAfterException("Authorization server responded with HTTP code 429 - too many requests.",
                                    headers::getFirst, exception));
                        }
                )
                .onStatus(httpStatus -> httpStatus == HttpStatus.SERVICE_UNAVAILABLE,
                        response -> {
                            HttpHeaders headers = response.headers().asHttpHeaders();
                            return httpError(response, exception -> retryAfterException("Authorization server responded with HTTP code 503 - service unavailable.",
                                    headers::getFirst, exception));
                        }
                )
                .onStatus(httpStatus -> !httpStatus.is2xxSuccessful(),
                        response -> httpError(response, exception -> new AccessTokenException(
                                "Authorization server responded with HTTP unexpected response code " + response.statusCode(), exception))
                )
                .bodyToMono(ClientCredentialsResponse.class);
            future = mono.toFuture();
        } catch (URISyntaxException e) {
            throw new IllegalArgumentException(e);
        }
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

    @Override
    public boolean supportsHealth() {
        return false;
    }
}
