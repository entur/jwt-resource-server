package org.entur.jwt.client.spring.resttemplate;

import org.entur.jwt.client.AbstractUrlAccessTokenProvider;
import org.entur.jwt.client.AccessTokenException;
import org.entur.jwt.client.AccessTokenUnavailableException;
import org.entur.jwt.client.ClientCredentialsResponse;
import org.entur.jwt.client.UrlAccessTokenProvider;
import org.springframework.core.io.Resource;
import org.springframework.http.*;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.ObjectReader;
import tools.jackson.databind.json.JsonMapper;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
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

public class RestTemplateUrlAccessTokenProvider extends AbstractUrlAccessTokenProvider {

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

    protected final ObjectReader reader;

    public RestTemplateUrlAccessTokenProvider(RestTemplate restTemplate, URL issueUrl, Map<String, Object> parameters, Map<String, Object> headers) {
        super(issueUrl, parameters, headers); // timeouts are baked into the resttemplate

        this.restTemplate = restTemplate;

        JsonMapper mapper = JsonMapper.builder().build();
        reader = mapper.readerFor(ClientCredentialsResponse.class);
    }

    protected ClientCredentialsResponse getToken() throws AccessTokenException {
        try {
            ResponseEntity<Resource> response = request(issueUrl, issueBody, issueHeaders);

            int responseCode = response.getStatusCode().value();
            if (responseCode != 200) {
                logger.info("Got unexpected response code {} when trying to issue token at {}", responseCode, issueUrl);
                if (responseCode == 503) { // service unavailable
                    throw new AccessTokenUnavailableException("Authorization server responded with HTTP code 503 - service unavailable. " + printHeadersIfPresent(response, "Retry-After"));
                } else if (responseCode == 429) { // too many calls
                    // see for example https://auth0.com/docs/policies/rate-limits
                    throw new AccessTokenUnavailableException("Authorization server responded with HTTP code 429 - too many requests. " + printHeadersIfPresent(response, "X-RateLimit-Limit", "X-RateLimit-Remaining", "X-RateLimit-Reset"));
                }
                throw new AccessTokenException("Authorization server responded with HTTP unexpected response code " + responseCode);
            }
            try (InputStream inputStream = getResponseContent(response)) {
                ClientCredentialsResponse clientCredentialsResponse = reader.readValue(inputStream);
                validate(clientCredentialsResponse);
                return clientCredentialsResponse;
            }
        } catch (IOException | JacksonException e) {
            throw new AccessTokenUnavailableException(e);
        }
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

    protected InputStream getResponseContent(ResponseEntity<Resource> response) throws IOException {
        Resource body = response.getBody();
        if(body != null) {
            return body.getInputStream();
        }
        throw new IOException("Empty body");
    }

    protected StringBuilder printHeadersIfPresent(ResponseEntity<Resource> c, String... headerNames) {
        return printResponseEntityHeadersIfPresent(c, headerNames);
    }

    @Override
    public boolean supportsHealth() {
        return false;
    }

}
