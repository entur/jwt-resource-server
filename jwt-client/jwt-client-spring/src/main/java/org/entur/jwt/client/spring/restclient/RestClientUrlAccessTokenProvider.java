package org.entur.jwt.client.spring.restclient;

import org.entur.jwt.client.AbstractUrlAccessTokenProvider;
import org.entur.jwt.client.AccessTokenException;
import org.entur.jwt.client.AccessTokenUnavailableException;
import org.entur.jwt.client.ClientCredentialsResponse;
import org.entur.jwt.client.UrlAccessTokenProvider;
import org.springframework.core.io.Resource;
import org.springframework.http.*;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;
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

public class RestClientUrlAccessTokenProvider extends AbstractUrlAccessTokenProvider {

    protected static StringBuilder printResponseEntityHeadersIfPresent(ClientHttpResponse response, String... headerNames) {
        StringBuilder builder = new StringBuilder();
        HttpHeaders headers = response.getHeaders();
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
    protected final ObjectReader reader;

    public RestClientUrlAccessTokenProvider(RestClient restClient, URL issueUrl, Map<String, Object> parameters, Map<String, Object> headers) {
        super(issueUrl, parameters, headers); // timeouts are baked into the resttemplate

        this.restClient = restClient;

        JsonMapper mapper = JsonMapper.builder().build();
        reader = mapper.readerFor(ClientCredentialsResponse.class);
    }

    protected ClientCredentialsResponse request(URL url, byte[] body, Map<String, Object> map) throws IOException {
        try {
            return restClient.post()
                    .uri(url.toURI())
                    .headers(headers -> {
                        headers.setAccept(Arrays.asList(MediaType.APPLICATION_JSON));
                        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

                        for (Entry<String, Object> entry : map.entrySet()) {
                            headers.set(entry.getKey(), entry.getValue().toString());
                        }
                    })
                    .body(body)
                    .contentLength(body.length)
                    .retrieve()
                    .onStatus(httpStatus -> httpStatus == HttpStatus.TOO_MANY_REQUESTS,
                            (request, response) -> new AccessTokenUnavailableException("Authorization server responded with HTTP code 429 - too many requests. " + printResponseEntityHeadersIfPresent(response, "Retry-After") )
                    )
                    .onStatus(httpStatus -> httpStatus == HttpStatus.SERVICE_UNAVAILABLE,
                            (request, response) -> new AccessTokenUnavailableException("Authorization server responded with HTTP code 503 - service unavailable. " + printResponseEntityHeadersIfPresent(response, "X-RateLimit-Limit", "X-RateLimit-Remaining", "X-RateLimit-Reset"))
                    )
                    .onStatus(httpStatus -> !httpStatus.is2xxSuccessful(),
                            (request, response) -> new AccessTokenException("Authorization server responded with HTTP unexpected response code " + response.getStatusCode())
                    )
                    .body(ClientCredentialsResponse.class);
        } catch (URISyntaxException e) {
            throw new IllegalArgumentException(e);
        } catch(RestClientException e) {
            throw new IOException(e);
        }
    }

    @Override
    public boolean supportsHealth() {
        return false;
    }

    protected ClientCredentialsResponse getToken() throws AccessTokenException {
        try {
            return request(issueUrl, issueBody, issueHeaders);
        } catch (IOException | JacksonException e) {
            throw new AccessTokenUnavailableException(e);
        }
    }

}
