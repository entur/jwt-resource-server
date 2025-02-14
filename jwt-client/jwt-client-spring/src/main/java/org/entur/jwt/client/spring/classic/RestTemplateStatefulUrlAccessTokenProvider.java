package org.entur.jwt.client.spring.classic;

import org.entur.jwt.client.AbstractStatefulUrlAccessTokenProvider;
import org.entur.jwt.client.UrlAccessTokenProvider;
import org.springframework.core.io.Resource;
import org.springframework.http.*;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.Arrays;
import java.util.Map;
import java.util.Map.Entry;

/**
 * 
 * RestTemplate access-token provider. Using {@linkplain UrlAccessTokenProvider}
 * would strictly be sufficient, but using RestTemplate is more convenient for
 * mocking.
 *
 */

public class RestTemplateStatefulUrlAccessTokenProvider extends AbstractStatefulUrlAccessTokenProvider<ResponseEntity<Resource>> {

    protected final RestTemplate restTemplate;

    public RestTemplateStatefulUrlAccessTokenProvider(RestTemplate restTemplate, URL issueUrl, Map<String, Object> parameters, Map<String, Object> headers, URL refreshUrl, URL revokeUrl) {
        super(issueUrl, parameters, headers, refreshUrl, revokeUrl);
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
            URI uri = url.toURI();
            return restTemplate.exchange(uri, HttpMethod.POST, request, Resource.class);
        } catch (URISyntaxException e) {
            throw new IllegalArgumentException(e);
        } catch(RestClientException e) {
            throw new IOException(e);
        }
    }

    @Override
    protected int getResponseStatusCode(ResponseEntity<Resource> response) throws IOException {
        return response.getStatusCode().value();
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
        return RestTemplateUrlAccessTokenProvider.printResponseEntityHeadersIfPresent(c, headerNames);
    }

}
