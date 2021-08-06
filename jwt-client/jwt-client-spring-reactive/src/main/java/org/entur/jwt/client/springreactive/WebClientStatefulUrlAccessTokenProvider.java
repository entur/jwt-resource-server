package org.entur.jwt.client.springreactive;

import org.entur.jwt.client.AbstractStatefulUrlAccessTokenProvider;
import org.entur.jwt.client.UrlAccessTokenProvider;
import org.springframework.core.io.Resource;
import org.springframework.http.*;
import org.springframework.web.reactive.function.client.WebClient;

import java.io.IOException;
import java.io.InputStream;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.Map;
import java.util.Map.Entry;

/**
 * RestTemplate access-token provider. Using {@linkplain UrlAccessTokenProvider}
 * would strictly be sufficient, but using RestTemplate is more convenient for
 * mocking.
 */

public class WebClientStatefulUrlAccessTokenProvider extends AbstractStatefulUrlAccessTokenProvider<ResponseEntity<Resource>> {

    protected final WebClient webClient;

    public WebClientStatefulUrlAccessTokenProvider(WebClient webClient, URL issueUrl, Map<String, Object> parameters, Map<String, Object> headers, URL refreshUrl, URL revokeUrl) {
        super(issueUrl, parameters, headers, refreshUrl, revokeUrl);
        this.webClient = webClient;
    }

    protected ResponseEntity<Resource> request(URL url, byte[] body, Map<String, Object> map) throws IOException {
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
                .toEntity(Resource.class)
                .block();
        } catch (URISyntaxException e) {
            throw new IllegalArgumentException(e);
        }
    }

    @Override
    protected int getResponseStatusCode(ResponseEntity<Resource> response) throws IOException {
        return response.getStatusCodeValue();
    }

    @Override
    protected InputStream getResponseContent(ResponseEntity<Resource> response) throws IOException {
        Resource body = response.getBody();
        if (body != null) {
            return body.getInputStream();
        }
        throw new IOException("Empty body");
    }

    @Override
    protected StringBuilder printHeadersIfPresent(ResponseEntity<Resource> c, String... headerNames) {
        return WebClientUrlAccessTokenProvider.printResponseEntityHeadersIfPresent(c, headerNames);
    }

}
