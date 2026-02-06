package org.entur.jwt.client.spring.restclient;

import org.apache.hc.client5.http.classic.HttpClient;
import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.client5.http.impl.classic.HttpClientBuilder;
import org.entur.jwt.client.properties.JwtClientProperties;
import org.entur.jwt.client.spring.JwtClientAutoConfiguration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.http.converter.json.JacksonJsonHttpMessageConverter;
import org.springframework.web.client.RestClient;

import java.util.concurrent.TimeUnit;

@Configuration
@EnableConfigurationProperties(JwtClientProperties.class)
public class RestClientJwtClientAutoConfiguration extends JwtClientAutoConfiguration {

    private static final Logger log = LoggerFactory.getLogger(RestClientJwtClientAutoConfiguration.class);

    @Bean
    public RestClient jwtRestClient(JwtClientProperties properties) {
        // use custom HTTP-client so that we do not get a cookie parse warning
        int connectTimeout = properties.getConnectTimeout();
        int readTimeout = properties.getReadTimeout();

        Long timeout = getTimeout(properties);

        if (timeout != null) {
            if (connectTimeout > timeout) {
                throw new IllegalArgumentException("Connect timeout of " + connectTimeout + "s exceeds cache refresh time of " + timeout + "s");
            }
            if (readTimeout > timeout) {
                throw new IllegalArgumentException("Read timeout of " + readTimeout + "s exceeds cache refresh time of " + timeout + "s");
            }
        }

        return RestClient.builder()
                .requestFactory(getHttpComponentsClientHttpRequestFactory(connectTimeout, readTimeout))
                .configureMessageConverters(client -> {
                    client.registerDefaults().withJsonConverter(new JacksonJsonHttpMessageConverter());
                })
                .build();
    }

    private static HttpComponentsClientHttpRequestFactory getHttpComponentsClientHttpRequestFactory(int connectTimeout, int readTimeout) {
        HttpComponentsClientHttpRequestFactory factory = new HttpComponentsClientHttpRequestFactory();

        RequestConfig requestConfig = RequestConfig.custom().setConnectTimeout(connectTimeout, TimeUnit.SECONDS).setResponseTimeout(readTimeout, TimeUnit.SECONDS).build();

        HttpClient httpClient = HttpClientBuilder.create()
                .disableCookieManagement()
                .disableAuthCaching()
                .disableAutomaticRetries()
                .disableRedirectHandling()
                .setDefaultRequestConfig(requestConfig)
                // do not keep alive, assuming creating new HTTP requests
                // will be the most robust approach
                .setConnectionReuseStrategy((a, b, c) -> false)
                .build();
        factory.setHttpClient(httpClient);
        return factory;
    }

    @Bean
    public RestClientJwtClientBeanDefinitionRegistryPostProcessorSupport jwtClientBeanDefinitionRegistryPostProcessorSupport(@Qualifier("jwtRestClient") RestClient restClient, JwtClientProperties properties) {
        return new RestClientJwtClientBeanDefinitionRegistryPostProcessorSupport(restClient, properties);
    }

}
