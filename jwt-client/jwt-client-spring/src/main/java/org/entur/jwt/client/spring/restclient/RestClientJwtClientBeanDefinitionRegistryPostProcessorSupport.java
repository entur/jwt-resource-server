package org.entur.jwt.client.spring.restclient;

import org.entur.jwt.client.AccessTokenProvider;
import org.entur.jwt.client.ClientCredentials;
import org.entur.jwt.client.properties.JwtClientProperties;
import org.entur.jwt.client.spring.JwtClientBeanDefinitionRegistryPostProcessorSupport;
import org.springframework.web.client.RestClient;

import java.net.URL;
import java.util.Map;

public class RestClientJwtClientBeanDefinitionRegistryPostProcessorSupport extends JwtClientBeanDefinitionRegistryPostProcessorSupport<RestClient> {

    public RestClientJwtClientBeanDefinitionRegistryPostProcessorSupport(RestClient client, JwtClientProperties properties) {
        super(client, properties);
    }

    @Override
    protected AccessTokenProvider newUrlAccessTokenProvider(RestClient client, URL issueURL, Map<String, Object> parameters, Map<String, Object> headers, ClientCredentials credentials) {
        return new RestClientUrlAccessTokenProvider(client, credentials.getIssueURL(), credentials.getParameters(), credentials.getHeaders());
    }

    @Override
    protected AccessTokenProvider newStatefulUrlAccessTokenProvider(RestClient client, URL issueURL, Map<String, Object> parameters, Map<String, Object> headers, URL refreshUrl, URL revokeUrl, ClientCredentials credentials) {
        return new RestClientStatefulUrlAccessTokenProvider(client, credentials.getIssueURL(), credentials.getParameters(), credentials.getHeaders(), refreshUrl, revokeUrl);
    }
}
