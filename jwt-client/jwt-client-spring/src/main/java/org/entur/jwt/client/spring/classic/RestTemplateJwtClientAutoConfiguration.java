package org.entur.jwt.client.spring.classic;

import org.apache.http.client.HttpClient;
import org.apache.http.client.config.CookieSpecs;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.impl.NoConnectionReuseStrategy;
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

import java.lang.reflect.Method;
import java.time.Duration;
import java.time.temporal.ChronoUnit;
import java.util.concurrent.TimeUnit;

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

        if(useHttpClient5()) {
            // i.e. spring boot 3.x
            return restTemplateBuilder
                    .requestFactory(() -> getHttpComponentsClientHttpRequestFactory((int)connectTimeout, (int)readTimeout))
                    .build();
        } else {
            // i.e. spring boot 2.x
            return restTemplateBuilder
                    .requestFactory(RestTemplateJwtClientAutoConfiguration::getHttpComponentsClientHttpRequestFactory)
                    .setConnectTimeout(Duration.of(connectTimeout, ChronoUnit.SECONDS))
                    .setReadTimeout(Duration.of(readTimeout, ChronoUnit.SECONDS))
                    .build();
        }
    }

    private static HttpComponentsClientHttpRequestFactory getHttpComponentsClientHttpRequestFactory() {
        HttpComponentsClientHttpRequestFactory factory = new HttpComponentsClientHttpRequestFactory();

        // https://stackoverflow.com/questions/7459279/httpclient-warning-cookie-rejected-illegal-domain-attribute
        RequestConfig customizedRequestConfig = RequestConfig.custom().setCookieSpec(CookieSpecs.IGNORE_COOKIES).build();

        HttpClient httpClient = HttpClientBuilder.create()
                .disableCookieManagement()
                .disableAuthCaching()
                .disableAutomaticRetries()
                .disableRedirectHandling()
                .setDefaultRequestConfig(customizedRequestConfig)
                // do not keep alive, assuming creating new HTTP requests
                // will be the most robust approach
                .setConnectionReuseStrategy(NoConnectionReuseStrategy.INSTANCE)
                .build();
        factory.setHttpClient(httpClient);
        return factory;
    }

    @Bean
    public RestTemplateJwtClientBeanDefinitionRegistryPostProcessorSupport jwtClientBeanDefinitionRegistryPostProcessorSupport(@Qualifier("jwtRestTemplate") RestTemplate restTemplate, SpringJwtClientProperties properties) {
        return new RestTemplateJwtClientBeanDefinitionRegistryPostProcessorSupport(restTemplate, properties);
    }

    private static HttpComponentsClientHttpRequestFactory getHttpComponentsClientHttpRequestFactory(int connectTimeout, int readTimeout) {
        HttpComponentsClientHttpRequestFactory factory = new HttpComponentsClientHttpRequestFactory();

        org.apache.hc.client5.http.config.RequestConfig requestConfig = org.apache.hc.client5.http.config.RequestConfig.custom().setConnectTimeout(connectTimeout, TimeUnit.SECONDS).setResponseTimeout(readTimeout, TimeUnit.SECONDS).build();

        org.apache.hc.client5.http.classic.HttpClient httpClient = org.apache.hc.client5.http.impl.classic.HttpClientBuilder.create()
                .disableCookieManagement()
                .disableAuthCaching()
                .disableAutomaticRetries()
                .disableRedirectHandling()
                .setDefaultRequestConfig(requestConfig)
                // do not keep alive, assuming creating new HTTP requests
                // will be the most robust approach
                .setConnectionReuseStrategy((a, b, c) -> false)
                .build();

        // workaround for incompatible spring 2.x vs spring 3.x
        try {
            Method setHttpClient = HttpComponentsClientHttpRequestFactory.class.getMethod("setHttpClient", org.apache.hc.client5.http.classic.HttpClient.class);
            setHttpClient.invoke(factory, httpClient);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        return factory;
    }

    public static boolean useHttpClient5() {
        try {
            HttpComponentsClientHttpRequestFactory.class.getMethod("setHttpClient", org.apache.hc.client5.http.classic.HttpClient.class);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

}
