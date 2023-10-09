package org.entur.jwt.client.spring.webflux;

import org.entur.jwt.client.AccessTokenProvider;
import org.entur.jwt.client.ClientCredentials;
import org.entur.jwt.client.spring.JwtClientBeanDefinitionRegistryPostProcessorSupport;
import org.entur.jwt.client.spring.SpringJwtClientProperties;
import org.springframework.web.reactive.function.client.WebClient;

import java.net.URL;
import java.util.Map;

public class WebfluxJwtClientBeanDefinitionRegistryPostProcessorSupport extends JwtClientBeanDefinitionRegistryPostProcessorSupport<WebClient> {

    public WebfluxJwtClientBeanDefinitionRegistryPostProcessorSupport(WebClient client, SpringJwtClientProperties properties) {
        super(client, properties);
    }

    @Override
    protected AccessTokenProvider newUrlAccessTokenProvider(WebClient client, URL issueURL, Map<String, Object> parameters, Map<String, Object> headers, ClientCredentials credentials) {
        return new WebClientUrlAccessTokenProvider(client, credentials.getIssueURL(), credentials.getParameters(), credentials.getHeaders());
    }

    @Override
    protected AccessTokenProvider newStatefulUrlAccessTokenProvider(WebClient client, URL issueURL, Map<String, Object> parameters, Map<String, Object> headers, URL refreshUrl, URL revokeUrl, ClientCredentials credentials) {
        return new WebClientStatefulUrlAccessTokenProvider(client, credentials.getIssueURL(), credentials.getParameters(), credentials.getHeaders(), refreshUrl, revokeUrl);
    }
}
