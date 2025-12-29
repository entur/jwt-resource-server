package org.entur.jwt.client.spring.restclient;

import org.entur.jwt.client.AbstractStatefulUrlAccessTokenProvider;
import org.entur.jwt.client.AccessTokenException;
import org.entur.jwt.client.AccessTokenUnavailableException;
import org.entur.jwt.client.ClientCredentialsResponse;
import org.entur.jwt.client.RefreshToken;
import org.entur.jwt.client.RefreshTokenException;
import org.entur.jwt.client.UrlAccessTokenProvider;
import org.springframework.core.io.Resource;
import org.springframework.http.*;
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
import java.util.Collections;
import java.util.Map;
import java.util.Map.Entry;
import static org.entur.jwt.client.spring.restclient.RestClientUrlAccessTokenProvider.*;
/**
 * 
 * RestTemplate access-token provider. Using {@linkplain UrlAccessTokenProvider}
 * would strictly be sufficient, but using RestTemplate is more convenient for
 * mocking.
 *
 */

public class RestClientStatefulUrlAccessTokenProvider extends AbstractStatefulUrlAccessTokenProvider {

    protected final RestClient restClient;
    protected final ObjectReader reader;

    public RestClientStatefulUrlAccessTokenProvider(RestClient restClient, URL issueUrl, Map<String, Object> parameters, Map<String, Object> headers, URL refreshUrl, URL revokeUrl) {
        super(issueUrl, parameters, headers, refreshUrl, revokeUrl);
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


    protected InputStream getResponseContent(ResponseEntity<Resource> response) throws IOException {
        Resource body = response.getBody();
        if(body != null) {
            return body.getInputStream();
        }
        throw new IOException("Empty body");
    }

    protected void close(long time) {
        RefreshToken threadSafeRefreshToken = this.refreshToken; // defensive copy
        if (threadSafeRefreshToken != null && threadSafeRefreshToken.isValid(time)) {
            this.refreshToken = null;

            byte[] revokeBody = createRevokeBody(threadSafeRefreshToken);

            try {
                restClient.post()
                        .uri(revokeUrl.toURI())
                        .headers(headers -> {
                            headers.setAccept(Arrays.asList(MediaType.APPLICATION_JSON));
                            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
                        })
                        .body(revokeBody)
                        .contentLength(revokeBody.length)
                        .retrieve()
                        .onStatus(httpStatus -> httpStatus == HttpStatus.TOO_MANY_REQUESTS,
                                (request, response) -> new RefreshTokenException("Authorization server responded with HTTP code 429 - too many requests. " + printResponseEntityHeadersIfPresent(response, "Retry-After") )
                        )
                        .onStatus(httpStatus -> httpStatus == HttpStatus.SERVICE_UNAVAILABLE,
                                (request, response) -> new RefreshTokenException("Authorization server responded with HTTP code 503 - service unavailable. " + printResponseEntityHeadersIfPresent(response, "X-RateLimit-Limit", "X-RateLimit-Remaining", "X-RateLimit-Reset"))
                        )
                        .toBodilessEntity();
            } catch (URISyntaxException e) {
                throw new IllegalArgumentException(e);
            } catch(Exception e) {
                logger.info("Unexpected exception when revoking refresh token", e);
            }
        }
    }

    protected ClientCredentialsResponse getToken(RefreshToken response) throws AccessTokenException {
        byte[] refreshBody = createRefreshBody(response);

        try {
            return request(refreshUrl, refreshBody, Collections.emptyMap());
        } catch (IOException | JacksonException e) {
            throw new AccessTokenUnavailableException(e);
        }
    }

    protected ClientCredentialsResponse getToken() throws AccessTokenException {
        try {
            return request(issueUrl, issueBody, issueHeaders);
        } catch (IOException | JacksonException e) {
            throw new AccessTokenUnavailableException(e);
        }
    }


}
