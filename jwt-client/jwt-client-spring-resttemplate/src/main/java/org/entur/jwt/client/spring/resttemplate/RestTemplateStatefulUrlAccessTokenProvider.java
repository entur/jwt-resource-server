package org.entur.jwt.client.spring.resttemplate;

import org.entur.jwt.client.AbstractStatefulUrlAccessTokenProvider;
import org.entur.jwt.client.AccessTokenException;
import org.entur.jwt.client.AccessTokenUnavailableException;
import org.entur.jwt.client.ClientCredentialsResponse;
import org.entur.jwt.client.RefreshToken;
import org.entur.jwt.client.RefreshTokenException;
import org.entur.jwt.client.UrlAccessTokenProvider;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;
import tools.jackson.core.JacksonException;

import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.Arrays;
import java.util.Collections;
import java.util.Map;
import java.util.Map.Entry;

/**
 * 
 * RestTemplate access-token provider. Using {@linkplain UrlAccessTokenProvider}
 * would strictly be sufficient, but using RestTemplate is more convenient for
 * mocking.
 *
 */

public class RestTemplateStatefulUrlAccessTokenProvider extends AbstractStatefulUrlAccessTokenProvider {

    protected final RestTemplate restTemplate;

    public RestTemplateStatefulUrlAccessTokenProvider(RestTemplate restTemplate, URL issueUrl, Map<String, Object> parameters, Map<String, Object> headers, URL refreshUrl, URL revokeUrl) {
        super(issueUrl, parameters, headers, refreshUrl, revokeUrl);
        this.restTemplate = restTemplate;
    }

    protected ResponseEntity<ClientCredentialsResponse> request(URL url, byte[] body, Map<String, Object> map) throws URISyntaxException {
        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(Arrays.asList(MediaType.APPLICATION_JSON));
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        for (Entry<String, Object> entry : map.entrySet()) {
            headers.set(entry.getKey(), entry.getValue().toString());
        }

        HttpEntity<byte[]> request = new HttpEntity<>(body, headers);

        URI uri = url.toURI();
        return restTemplate.exchange(uri, HttpMethod.POST, request, ClientCredentialsResponse.class);
    }

    protected StringBuilder printHeadersIfPresent(ResponseEntity<?> c, String... headerNames) {
        return RestTemplateUrlAccessTokenProvider.printResponseEntityHeadersIfPresent(c, headerNames);
    }

    protected void close(long time) {
        RefreshToken threadSafeRefreshToken = this.refreshToken; // defensive copy
        if (threadSafeRefreshToken != null && threadSafeRefreshToken.isValid(time)) {
            this.refreshToken = null;

            byte[] revokeBody = createRevokeBody(threadSafeRefreshToken);

            try {
                HttpHeaders headers = new HttpHeaders();
                headers.setAccept(Arrays.asList(MediaType.APPLICATION_JSON));
                headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

                HttpEntity<byte[]> request = new HttpEntity<>(revokeBody, headers);

                URI uri = revokeUrl.toURI();
                ResponseEntity<Void> response = restTemplate.exchange(uri, HttpMethod.POST, request, Void.class);

                int responseCode = response.getStatusCode().value();
                if (responseCode != 200) {
                    logger.info("Unexpected response code {} when revoking refresh token", responseCode);

                    if (responseCode == 503) { // service unavailable
                        logger.info("Got unexpected response code {} when revoking refresh token at {}. {}", responseCode, revokeUrl, printHeadersIfPresent(response, "Retry-After"));
                    } else if (responseCode == 429) { // too many calls
                        // see for example https://auth0.com/docs/policies/rate-limits
                        logger.info("Got unexpected response code {} when revoking refresh token at {}. {}", responseCode, revokeUrl, printHeadersIfPresent(response, "X-RateLimit-Limit", "X-RateLimit-Remaining", "X-RateLimit-Reset"));
                    } else {
                        logger.info("Got unexpected response code {} when revoking refresh token at {}. {}", responseCode, revokeUrl);
                    }
                }
            } catch (URISyntaxException e) {
                throw new IllegalArgumentException(e);
            } catch (Exception e) {
                logger.info("Unexpected exception when revoking refresh token", e);
            }
        }
    }

    protected ClientCredentialsResponse getToken(RefreshToken refreshToken) throws AccessTokenException {
        byte[] refreshBody = createRefreshBody(refreshToken);

        try {
            ResponseEntity<ClientCredentialsResponse> response = request(refreshUrl, refreshBody, Collections.emptyMap());

            int responseCode = response.getStatusCode().value();
            if (responseCode != 200) {
                logger.info("Got unexpected response code {} when trying to refresh token at {}", responseCode, refreshUrl);
                if (responseCode == 503) { // service unavailable
                    throw new AccessTokenUnavailableException("Authorization server responded with HTTP code 503 - service unavailable. " + printHeadersIfPresent(response, "Retry-After"));
                } else if (responseCode == 429) { // too many calls
                    // see for example https://auth0.com/docs/policies/rate-limits
                    throw new AccessTokenUnavailableException("Authorization server responded with HTTP code 429 - too many requests. " + printHeadersIfPresent(response, "X-RateLimit-Limit", "X-RateLimit-Remaining", "X-RateLimit-Reset"));
                }

                throw new RefreshTokenException("Authorization server responded with HTTP unexpected response code " + responseCode);
            }
            ClientCredentialsResponse clientCredentialsResponse = response.getBody();
            validate(clientCredentialsResponse);
            return clientCredentialsResponse;
        } catch (URISyntaxException e) {
            throw new IllegalArgumentException(e);
        } catch (RestClientException | JacksonException e) {
            throw new AccessTokenUnavailableException(e);
        }
    }

    protected ClientCredentialsResponse getToken() throws AccessTokenException {
        try {
            ResponseEntity<ClientCredentialsResponse> response = request(issueUrl, issueBody, issueHeaders);

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
        }
    }

}
