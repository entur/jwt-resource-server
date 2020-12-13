package org.entur.jwt.client.spring;

import java.io.IOException;
import java.io.InputStream;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.Arrays;
import java.util.Map;
import java.util.Map.Entry;

import org.entur.jwt.client.AbstractStatefulUrlAccessTokenProvider;
import org.entur.jwt.client.UrlAccessTokenProvider;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestTemplate;

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
        return RestTemplateUrlAccessTokenProvider.printResponseEntityHeadersIfPresent(c, headerNames);
    }

}
