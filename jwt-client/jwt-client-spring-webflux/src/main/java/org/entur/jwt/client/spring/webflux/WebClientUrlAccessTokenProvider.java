package org.entur.jwt.client.spring.webflux;

import org.entur.jwt.client.AbstractUrlAccessTokenProvider;
import org.entur.jwt.client.AccessTokenException;
import org.entur.jwt.client.AccessTokenUnavailableException;
import org.entur.jwt.client.ClientCredentialsResponse;
import org.entur.jwt.client.UrlAccessTokenProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.net.URISyntaxException;
import java.net.URL;
import java.util.Map;
import java.util.Map.Entry;
import java.util.concurrent.ExecutionException;

/**
 * WebClient access-token provider. Using {@linkplain UrlAccessTokenProvider}
 * would strictly be sufficient, but using WebClient is more convenient for
 * mocking.
 */

public class WebClientUrlAccessTokenProvider extends AbstractUrlAccessTokenProvider {

    protected final WebClient webClient;

    protected static final Logger logger = LoggerFactory.getLogger(WebClientUrlAccessTokenProvider.class);

    public WebClientUrlAccessTokenProvider(WebClient webClient, URL issueUrl, Map<String, Object> parameters, Map<String, Object> headers) {
        super(issueUrl, parameters, headers);

        this.webClient = webClient;
    }

    protected ClientCredentialsResponse getToken() throws AccessTokenException {
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
                        response -> Mono.error(new AccessTokenUnavailableException("Authorization server responded with HTTP code 429 - too many requests."))
                )
                .onStatus(httpStatus -> httpStatus == HttpStatus.SERVICE_UNAVAILABLE,
                        response -> Mono.error(new AccessTokenUnavailableException("Authorization server responded with HTTP code 503 - service unavailable."))
                )
                .onStatus(httpStatus -> !httpStatus.is2xxSuccessful(),
                        response -> Mono.error(new AccessTokenException("Authorization server responded with HTTP unexpected response code " + response.statusCode()))
                )
                .bodyToMono(ClientCredentialsResponse.class);
            ClientCredentialsResponse clientCredentialsResponse = mono.toFuture().get();
            validate(clientCredentialsResponse);
            return clientCredentialsResponse;
        } catch (URISyntaxException e) {
            throw new IllegalArgumentException(e);
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

    @Override
    public boolean supportsHealth() {
        return false;
    }
}
