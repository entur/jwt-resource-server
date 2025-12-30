package org.entur.jwt.client.spring.restclient;

import org.entur.jwt.client.AbstractUrlAccessTokenProvider;
import org.entur.jwt.client.AccessTokenException;
import org.entur.jwt.client.AccessTokenUnavailableException;
import org.entur.jwt.client.ClientCredentialsResponse;
import org.entur.jwt.client.UrlAccessTokenProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.web.client.HttpStatusCodeException;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;

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

public class RestClientUrlAccessTokenProvider extends AbstractUrlAccessTokenProvider {

    protected static final Logger LOGGER = LoggerFactory.getLogger(RestClientUrlAccessTokenProvider.class);

    protected static StringBuilder printResponseEntityHeadersIfPresent(HttpHeaders headers, String... headerNames) {
        StringBuilder builder = new StringBuilder();
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

    protected final RestClient restClient;

    public RestClientUrlAccessTokenProvider(RestClient restClient, URL issueUrl, Map<String, Object> parameters, Map<String, Object> headers) {
        super(issueUrl, parameters, headers); // timeouts are baked into the resttemplate

        this.restClient = restClient;
    }

    @Override
    public boolean supportsHealth() {
        return false;
    }

    protected ClientCredentialsResponse getToken() throws AccessTokenException {
        try {
            ClientCredentialsResponse clientCredentialsResponse = restClient.post()
                .uri(issueUrl.toURI())
                .headers(headers -> {
                    headers.setAccept(Arrays.asList(MediaType.APPLICATION_JSON));
                    headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

                    for (Entry<String, Object> entry : issueHeaders.entrySet()) {
                        headers.set(entry.getKey(), entry.getValue().toString());
                    }
                })
                .body(issueBody)
                .contentLength(issueBody.length)
                .retrieve()
                .body(ClientCredentialsResponse.class);

            validate(clientCredentialsResponse);
            return clientCredentialsResponse;
        } catch (URISyntaxException e) {
            throw new IllegalArgumentException(e);
        } catch (HttpStatusCodeException e) {
            int responseCode = e.getStatusCode().value();
            if(LOGGER.isInfoEnabled()) LOGGER.info("Got unexpected response code {} when trying to issue token at {}", responseCode, issueUrl);
            if (responseCode == 503) { // service unavailable
                throw new AccessTokenUnavailableException("Authorization server responded with HTTP code 503 - service unavailable. " + printResponseEntityHeadersIfPresent(e.getResponseHeaders(), "Retry-After"));
            } else if (responseCode == 429) { // too many calls
                // see for example https://auth0.com/docs/policies/rate-limits
                throw new AccessTokenUnavailableException("Authorization server responded with HTTP code 429 - too many requests. " + printResponseEntityHeadersIfPresent(e.getResponseHeaders(), "X-RateLimit-Limit", "X-RateLimit-Remaining", "X-RateLimit-Reset"));
            }
            throw new AccessTokenException("Authorization server responded with HTTP unexpected response code " + responseCode);
        } catch(RestClientException e) {
            throw new AccessTokenUnavailableException(e);
        }
    }

}
