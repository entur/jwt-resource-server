package org.entur.jwt.client.spring.restclient;

import org.entur.jwt.client.AbstractStatefulUrlAccessTokenProvider;
import org.entur.jwt.client.AccessTokenException;
import org.entur.jwt.client.AccessTokenUnavailableException;
import org.entur.jwt.client.ClientCredentialsResponse;
import org.entur.jwt.client.RefreshToken;
import org.entur.jwt.client.UrlAccessTokenProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.web.client.HttpStatusCodeException;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;

import java.net.URISyntaxException;
import java.net.URL;
import java.util.Arrays;
import java.util.Collections;
import java.util.Map;
import java.util.Map.Entry;

import static org.entur.jwt.client.spring.restclient.RestClientUrlAccessTokenProvider.printResponseEntityHeadersIfPresent;
/**
 * 
 * {@link RestClient} access-token provider.
 *
 */

public class RestClientStatefulUrlAccessTokenProvider extends AbstractStatefulUrlAccessTokenProvider {

    protected static final Logger LOGGER = LoggerFactory.getLogger(RestClientStatefulUrlAccessTokenProvider.class);

    protected final RestClient restClient;

    public RestClientStatefulUrlAccessTokenProvider(RestClient restClient, URL issueUrl, Map<String, Object> parameters, Map<String, Object> headers, URL refreshUrl, URL revokeUrl) {
        super(issueUrl, parameters, headers, refreshUrl, revokeUrl);
        this.restClient = restClient;
    }

    protected ClientCredentialsResponse request(URL url, byte[] body, Map<String, Object> headersMap) throws URISyntaxException, AccessTokenUnavailableException {
        ClientCredentialsResponse clientCredentialsResponse = restClient.post()
            .uri(url.toURI())
            .headers(headers -> {
                headers.setAccept(Arrays.asList(MediaType.APPLICATION_JSON));
                headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

                for (Entry<String, Object> entry : headersMap.entrySet()) {
                    headers.set(entry.getKey(), entry.getValue().toString());
                }
            })
            .body(body)
            .contentLength(body.length)
            .retrieve()
            .body(ClientCredentialsResponse.class);

        validate(clientCredentialsResponse);
        return clientCredentialsResponse;
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
                    .toBodilessEntity();
            } catch (URISyntaxException e) {
                throw new IllegalArgumentException(e);
            } catch (HttpStatusCodeException e) {
                int responseCode = e.getStatusCode().value();
                if (responseCode == 503) { // service unavailable
                    if(LOGGER.isInfoEnabled()) LOGGER.info("Got unexpected response code {} when trying to revoke refresh token at {}. {}", responseCode, revokeUrl, printResponseEntityHeadersIfPresent(e.getResponseHeaders(), "Retry-After"));
                } else if (responseCode == 429) { // too many calls
                    // see for example https://auth0.com/docs/policies/rate-limits
                    if(LOGGER.isInfoEnabled()) LOGGER.info("Got unexpected response code {} when trying to revoke refresh token at {}. {}", responseCode, revokeUrl, printResponseEntityHeadersIfPresent(e.getResponseHeaders(), "X-RateLimit-Limit", "X-RateLimit-Remaining", "X-RateLimit-Reset"));
                } else {
                    if(LOGGER.isInfoEnabled()) LOGGER.info("Unexpected exception when revoking refresh token", e);
                }
            } catch(Exception e) {
                if(LOGGER.isInfoEnabled()) LOGGER.info("Unexpected exception when revoking refresh token", e);
            }
        }
    }

    protected ClientCredentialsResponse getToken(RefreshToken response) throws AccessTokenException {
        byte[] refreshBody = createRefreshBody(response);

        try {
            return request(refreshUrl, refreshBody, Collections.emptyMap());
        } catch (URISyntaxException e) {
            throw new IllegalArgumentException(e);
        } catch (HttpStatusCodeException e) {
            int responseCode = e.getStatusCode().value();
            if(LOGGER.isInfoEnabled()) LOGGER.info("Got unexpected response code {} when trying to refresh token at {}", responseCode, refreshUrl);
            if (responseCode == 503) { // service unavailable
                throw new AccessTokenUnavailableException("Authorization server responded with HTTP code 503 - service unavailable when refreshing token. " + printResponseEntityHeadersIfPresent(e.getResponseHeaders(), "Retry-After"));
            } else if (responseCode == 429) { // too many calls
                // see for example https://auth0.com/docs/policies/rate-limits
                throw new AccessTokenUnavailableException("Authorization server responded with HTTP code 429 - too many requests when refreshing token. " + printResponseEntityHeadersIfPresent(e.getResponseHeaders(), "X-RateLimit-Limit", "X-RateLimit-Remaining", "X-RateLimit-Reset"));
            }
            throw new AccessTokenException("Authorization server responded with HTTP unexpected response code " + responseCode + " when refreshing token");
        } catch(RestClientException e) {
            throw new AccessTokenUnavailableException(e);
        }
    }

    protected ClientCredentialsResponse getToken() throws AccessTokenException {
        try {
            return request(issueUrl, issueBody, issueHeaders);
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
