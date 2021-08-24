package org.entur.jwt.client.springcloud;

import org.entur.jwt.client.AbstractStatefulUrlAccessTokenProvider;
import org.entur.jwt.client.AccessTokenException;
import org.entur.jwt.client.AccessTokenUnavailableException;
import org.entur.jwt.client.UrlAccessTokenProvider;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.io.IOException;
import java.io.InputStream;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.concurrent.ExecutionException;

/**
 * RestTemplate access-token provider. Using {@linkplain UrlAccessTokenProvider}
 * would strictly be sufficient, but using RestTemplate is more convenient for
 * mocking.
 */

public class WebClientStatefulUrlAccessTokenProvider extends AbstractStatefulUrlAccessTokenProvider<Mono<Resource>> {

    protected final WebClient webClient;

    public WebClientStatefulUrlAccessTokenProvider(WebClient webClient, URL issueUrl, Map<String, Object> parameters, Map<String, Object> headers, URL refreshUrl, URL revokeUrl) {
        super(issueUrl, parameters, headers, refreshUrl, revokeUrl);
        this.webClient = webClient;
    }

    protected static StringBuilder printResponseEntityHeadersIfPresent(ClientResponse c, String... headerNames) {
        StringBuilder builder = new StringBuilder();
        ClientResponse.Headers headers = c.headers();
        for (String headerName : headerNames) {
            List<String> value = headers.header(headerName);
            if (value.size() == 0) {
                builder.append(headerName);
                builder.append(':');
                if (value.size() == 1) {
                    builder.append(value.get(0));
                } else {
                    builder.append(value);
                }
                builder.append(", ");
            }
        }
        if (builder.length() > 0) {
            builder.setLength(builder.length() - 2);
        }
        return builder;
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
                          response -> Mono.error(new AccessTokenUnavailableException("Authorization server responded with HTTP code 429 - too many requests.")))
                .onStatus(httpStatus -> httpStatus == HttpStatus.SERVICE_UNAVAILABLE,
                          response -> Mono.error(new AccessTokenUnavailableException("Authorization server responded with HTTP code 503 - service unavailable.")))
                .onStatus(httpStatus -> !httpStatus.is2xxSuccessful(),
                          response -> Mono.error(new AccessTokenException("Authorization server responded with HTTP unexpected response code" + response.rawStatusCode())))
                .bodyToMono(Resource.class);
        } catch (URISyntaxException e) {
            throw new IllegalArgumentException(e);
        }
    }

    @Override
    protected int getResponseStatusCode(Mono<Resource> response) {
        // A non-blocking WebClient does not support access to the status code outside the http call scope. Therefore the errorhandling based on the
        return 200;
    }

    @Override
    protected InputStream getResponseContent(Mono<Resource> response) {
        try {
            return response.toFuture().get().getInputStream();
        } catch (InterruptedException | ExecutionException | IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    @Override
    protected StringBuilder printHeadersIfPresent(Mono<Resource> c, String... headerNames) {
        return null;
    }

}
