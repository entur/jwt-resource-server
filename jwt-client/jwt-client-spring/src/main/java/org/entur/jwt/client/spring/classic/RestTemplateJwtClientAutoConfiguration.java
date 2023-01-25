package org.entur.jwt.client.spring.classic;

import org.apache.http.client.HttpClient;
import org.apache.http.conn.ConnectionKeepAliveStrategy;
import org.apache.http.impl.client.HttpClientBuilder;
import org.entur.jwt.client.spring.JwtClientAutoConfiguration;
import org.entur.jwt.client.spring.SpringJwtClientProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.web.client.RestTemplate;

import java.time.Duration;
import java.time.temporal.ChronoUnit;

@Configuration
@EnableConfigurationProperties(SpringJwtClientProperties.class)
public class RestTemplateJwtClientAutoConfiguration extends JwtClientAutoConfiguration {

    private static Logger log = LoggerFactory.getLogger(RestTemplateJwtClientAutoConfiguration.class);

    @Bean
    @Qualifier("jwtRestTemplate")
    public RestTemplate jwtRestTemplate(RestTemplateBuilder restTemplateBuilder, SpringJwtClientProperties properties) {
        // use custom HTTP-client so that we do not get a cookie parse warning
        long connectTimeout = properties.getConnectTimeout();
        long readTimeout = properties.getReadTimeout();

        Long timeout = getTimeout(properties);

        if(timeout != null) {
            if(connectTimeout > timeout) {
                throw new IllegalArgumentException("Connect timeout of " + connectTimeout + "s exceeds cache refresh time of " + timeout + "s");
            }
            if(readTimeout > timeout) {
                throw new IllegalArgumentException("Read timeout of " + readTimeout + "s exceeds cache refresh time of " + timeout + "s");
            }
        }

        return restTemplateBuilder
                .requestFactory(RestTemplateJwtClientAutoConfiguration::getHttpComponentsClientHttpRequestFactory)
                .setConnectTimeout(Duration.of(connectTimeout, ChronoUnit.SECONDS))
                .setReadTimeout(Duration.of(readTimeout, ChronoUnit.SECONDS))
                .build();
    }

    private static HttpComponentsClientHttpRequestFactory getHttpComponentsClientHttpRequestFactory() {
        HttpComponentsClientHttpRequestFactory factory = new HttpComponentsClientHttpRequestFactory();

        HttpClient httpClient = HttpClientBuilder.create()
                .disableCookieManagement()
                .disableAuthCaching()
                .disableAutomaticRetries()
                .disableRedirectHandling()

                // do not keep alive, assuming creating new HTTP requests
                // will be the most robust approach
                .setKeepAliveStrategy((response, context) -> {
                    return -1;
                })
                .build();
        factory.setHttpClient(httpClient);
        return factory;
    }

    @Bean
    public RestTemplateJwtClientBeanDefinitionRegistryPostProcessorSupport jwtClientBeanDefinitionRegistryPostProcessorSupport(@Qualifier("jwtRestTemplate") RestTemplate restTemplate, SpringJwtClientProperties properties) {
        return new RestTemplateJwtClientBeanDefinitionRegistryPostProcessorSupport(restTemplate, properties);
    }


}
