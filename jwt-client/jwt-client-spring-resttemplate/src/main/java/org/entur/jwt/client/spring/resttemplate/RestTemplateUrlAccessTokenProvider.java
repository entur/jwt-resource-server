package org.entur.jwt.client.spring.resttemplate;

import org.entur.jwt.client.AbstractUrlAccessTokenProvider;
import org.entur.jwt.client.AccessTokenException;
import org.entur.jwt.client.AccessTokenUnavailableException;
import org.entur.jwt.client.ClientCredentialsResponse;
import org.entur.jwt.client.UrlAccessTokenProvider;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

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

    public RestTemplateUrlAccessTokenProvider(RestTemplate restTemplate, URL issueUrl, Map<String, Object> parameters, Map<String, Object> headers) {
        super(issueUrl, parameters, headers); // timeouts are baked into the resttemplate

        this.restTemplate = restTemplate;
    }

    protected ClientCredentialsResponse getToken() throws AccessTokenException {
        try {
            HttpHeaders headers = new HttpHeaders();
            headers.setAccept(Arrays.asList(MediaType.APPLICATION_JSON));
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

            for (Entry<String, Object> entry : issueHeaders.entrySet()) {
                headers.set(entry.getKey(), entry.getValue().toString());
            }

            HttpEntity<byte[]> request = new HttpEntity<>(issueBody, headers);

            URI uri = issueUrl.toURI();
            ResponseEntity<ClientCredentialsResponse> response = restTemplate.exchange(uri, HttpMethod.POST, request, ClientCredentialsResponse.class);

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

            ClientCredentialsResponse clientCredentialsResponse = response.getBody();
            validate(clientCredentialsResponse);
            return clientCredentialsResponse;
        } catch (URISyntaxException e) {
            throw new IllegalArgumentException(e);
        } catch(RestClientException e) {
            throw new AccessTokenUnavailableException(e);
        }
    }

    protected StringBuilder printHeadersIfPresent(ResponseEntity<ClientCredentialsResponse> c, String... headerNames) {
        return printResponseEntityHeadersIfPresent(c, headerNames);
    }

    @Override
    public boolean supportsHealth() {
        return false;
    }

}
