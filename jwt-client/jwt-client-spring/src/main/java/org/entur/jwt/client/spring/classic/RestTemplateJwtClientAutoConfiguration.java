package org.entur.jwt.client.spring.classic;

import org.apache.hc.client5.http.classic.HttpClient;
import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.client5.http.impl.classic.HttpClientBuilder;
import org.entur.jwt.client.properties.JwtClientProperties;
import org.entur.jwt.client.spring.JwtClientAutoConfiguration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.web.client.RestTemplate;

import java.util.concurrent.TimeUnit;

@Configuration
@EnableConfigurationProperties(JwtClientProperties.class)
public class RestTemplateJwtClientAutoConfiguration extends JwtClientAutoConfiguration {

    private static final Logger log = LoggerFactory.getLogger(RestTemplateJwtClientAutoConfiguration.class);

    @Bean
    @Qualifier("jwtRestTemplate")
    public RestTemplate jwtRestTemplate(RestTemplateBuilder restTemplateBuilder, JwtClientProperties properties) {
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

        return restTemplateBuilder
                .requestFactory(() -> getHttpComponentsClientHttpRequestFactory(connectTimeout, readTimeout))
                .build();
    }

    private static HttpComponentsClientHttpRequestFactory getHttpComponentsClientHttpRequestFactory(int connectTimeout, int readTimeout) {
        HttpComponentsClientHttpRequestFactory factory = new HttpComponentsClientHttpRequestFactory();

        // https://stackoverflow.com/questions/7459279/httpclient-warning-cookie-rejected-illegal-domain-attribute
        //RequestConfig customizedRequestConfig = RequestConfig.custom().setCookieSpec(CookieSpecSupport.createDefaultBuilder().IGNORE_COOKIES).build();

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
    public RestTemplateJwtClientBeanDefinitionRegistryPostProcessorSupport jwtClientBeanDefinitionRegistryPostProcessorSupport(@Qualifier("jwtRestTemplate") RestTemplate restTemplate, JwtClientProperties properties) {
        return new RestTemplateJwtClientBeanDefinitionRegistryPostProcessorSupport(restTemplate, properties);
    }


}
