package org.entur.jwt.client.springreactive;

import org.entur.jwt.client.AbstractUrlAccessTokenProvider;
import org.entur.jwt.client.UrlAccessTokenProvider;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.reactive.function.client.WebClient;

import java.io.IOException;
import java.io.InputStream;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

/**
 * RestTemplate access-token provider. Using {@linkplain UrlAccessTokenProvider}
 * would strictly be sufficient, but using RestTemplate is more convenient for
 * mocking.
 */

public class WebClientUrlAccessTokenProvider extends AbstractUrlAccessTokenProvider<ResponseEntity<Resource>> {

    protected static StringBuilder printResponseEntityHeadersIfPresent(ResponseEntity<?> c, String... headerNames) {
        StringBuilder builder = new StringBuilder();
        HttpHeaders headers = c.getHeaders();
        for (String headerName : headerNames) {
            List<String> value = headers.get(headerName);
            if (value != null) {
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

    protected final WebClient webClient;

    public WebClientUrlAccessTokenProvider(WebClient webClient, URL issueUrl, Map<String, Object> parameters, Map<String, Object> headers) {
        super(issueUrl, parameters, headers); // timeouts are baked into the resttemplate

        this.webClient = webClient;
    }

    protected ResponseEntity<Resource> request(URL url, byte[] body, Map<String, Object> map) {
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
        return printResponseEntityHeadersIfPresent(c, headerNames);
    }

}
