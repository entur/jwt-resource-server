package org.entur.jwt.client.spring.resttemplate;

import org.entur.jwt.client.AccessTokenProvider;
import org.entur.jwt.client.ClientCredentials;
import org.entur.jwt.client.properties.JwtClientProperties;
import org.entur.jwt.client.spring.JwtClientBeanDefinitionRegistryPostProcessorSupport;
import org.springframework.web.client.RestTemplate;

import java.net.URL;
import java.util.Map;

public class RestTemplateJwtClientBeanDefinitionRegistryPostProcessorSupport extends JwtClientBeanDefinitionRegistryPostProcessorSupport<RestTemplate> {

    public RestTemplateJwtClientBeanDefinitionRegistryPostProcessorSupport(RestTemplate client, JwtClientProperties properties) {
        super(client, properties);
    }

    @Override
    protected AccessTokenProvider newUrlAccessTokenProvider(RestTemplate client, URL issueURL, Map<String, Object> parameters, Map<String, Object> headers, ClientCredentials credentials) {
        return new RestTemplateUrlAccessTokenProvider(client, credentials.getIssueURL(), credentials.getParameters(), credentials.getHeaders());
    }

    @Override
    protected AccessTokenProvider newStatefulUrlAccessTokenProvider(RestTemplate client, URL issueURL, Map<String, Object> parameters, Map<String, Object> headers, URL refreshUrl, URL revokeUrl, ClientCredentials credentials) {
        return new RestTemplateStatefulUrlAccessTokenProvider(client, credentials.getIssueURL(), credentials.getParameters(), credentials.getHeaders(), refreshUrl, revokeUrl);
    }
}
