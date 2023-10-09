package org.entur.jwt.client.spring.webflux;

import org.entur.jwt.client.AbstractUrlAccessTokenProvider;
import org.entur.jwt.client.AccessTokenException;
import org.entur.jwt.client.AccessTokenUnavailableException;
import org.entur.jwt.client.UrlAccessTokenProvider;
import org.entur.jwt.client.spring.actuate.AccessTokenProviderHealthIndicator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.io.IOException;
import java.io.InputStream;
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

public class WebClientUrlAccessTokenProvider extends AbstractUrlAccessTokenProvider<Mono<Resource>> {

    protected final WebClient webClient;

    protected static final Logger logger = LoggerFactory.getLogger(AccessTokenProviderHealthIndicator.class);


    public WebClientUrlAccessTokenProvider(WebClient webClient, URL issueUrl, Map<String, Object> parameters, Map<String, Object> headers) {
        super(issueUrl, parameters, headers);

        this.webClient = webClient;
    }

    protected Mono<Resource> request(URL url, byte[] body, Map<String, Object> map) {
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
                          response -> Mono.error(new AccessTokenException("Authorization server responded with HTTP unexpected response code " + response.rawStatusCode()))
                )
                .bodyToMono(Resource.class);
        } catch (URISyntaxException e) {
            throw new IllegalArgumentException(e);
        }
    }

    @Override
    protected int getResponseStatusCode(Mono<Resource> response) {
        // A non-blocking WebClient does not support access to the status code outside the http call scope. Therefore the error handling based on HttpStatus is part of the WebClient call chain.
        return 200;
    }

    @Override
    protected InputStream getResponseContent(Mono<Resource> response) throws IOException {
        try {
            return response.toFuture().get().getInputStream();
        } catch (InterruptedException | ExecutionException e) {
            e.printStackTrace();
        }
        return null;
    }

    @Override
    protected StringBuilder printHeadersIfPresent(Mono<Resource> c, String... headerNames) {
        return null;
    }

    @Override
    public boolean supportsHealth() {
        return false;
    }
}
