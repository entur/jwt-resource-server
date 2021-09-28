package org.entur.jwt.client.spring.classic;

import org.entur.jwt.client.AbstractUrlAccessTokenProvider;
import org.entur.jwt.client.UrlAccessTokenProvider;
import org.springframework.core.io.Resource;
import org.springframework.http.*;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;
import java.io.InputStream;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

/**
 * 
 * RestTemplate access-token provider. Using {@linkplain UrlAccessTokenProvider}
 * would strictly be sufficient, but using RestTemplate is more convenient for
 * mocking.
 *
 */

public class RestTemplateUrlAccessTokenProvider extends AbstractUrlAccessTokenProvider<ResponseEntity<Resource>> {

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

    protected final RestTemplate restTemplate;

    public RestTemplateUrlAccessTokenProvider(RestTemplate restTemplate, URL issueUrl, Map<String, Object> parameters, Map<String, Object> headers) {
        super(issueUrl, parameters, headers); // timeouts are baked into the resttemplate

        this.restTemplate = restTemplate;
    }

    protected ResponseEntity<Resource> request(URL url, byte[] body, Map<String, Object> map) throws IOException {
        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(Arrays.asList(MediaType.APPLICATION_JSON));
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        for (Entry<String, Object> entry : map.entrySet()) {
            headers.set(entry.getKey(), entry.getValue().toString());
        }

        HttpEntity<byte[]> request = new HttpEntity<>(body, headers);

        try {
            return restTemplate.exchange(url.toURI(), HttpMethod.POST, request, Resource.class);
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
        if(body != null) {
            return body.getInputStream();
        }
        throw new IOException("Empty body");
    }

    @Override
    protected StringBuilder printHeadersIfPresent(ResponseEntity<Resource> c, String... headerNames) {
        return printResponseEntityHeadersIfPresent(c, headerNames);
    }

    @Override
    public boolean supportsHealth() {
        return false;
    }

}
