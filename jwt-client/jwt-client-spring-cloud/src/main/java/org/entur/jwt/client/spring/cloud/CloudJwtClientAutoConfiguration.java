package org.entur.jwt.client.spring.cloud;

import io.netty.channel.ChannelOption;
import io.netty.handler.timeout.ReadTimeoutHandler;
import org.entur.jwt.client.spring.JwtClientAutoConfiguration;
import org.entur.jwt.client.spring.SpringJwtClientProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.netty.http.client.HttpClient;

@EnableConfigurationProperties(SpringJwtClientProperties.class)
public class CloudJwtClientAutoConfiguration extends JwtClientAutoConfiguration {


    private static Logger log = LoggerFactory.getLogger(CloudJwtClientAutoConfiguration.class);

    public CloudJwtClientAutoConfiguration() {
        log.info("Configre " + getClass().getSimpleName());
    }

    @Bean
    @Qualifier("jwtWebClient")
    public WebClient jwtWebClient(WebClient.Builder webClientBuilder, SpringJwtClientProperties properties) {

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

        return webClientBuilder.clientConnector(
            new ReactorClientHttpConnector(HttpClient.create()
                .doOnConnected(connection -> connection.addHandler(new ReadTimeoutHandler(((int) readTimeout))))
                                               .option(ChannelOption.CONNECT_TIMEOUT_MILLIS, (int) (connectTimeout*1000))
            )
        ).build();
    }

    @Bean
    public CloudJwtClientBeanDefinitionRegistryPostProcessorSupport jwtClientBeanDefinitionRegistryPostProcessorSupport(@Qualifier("jwtWebClient") WebClient webClient, SpringJwtClientProperties properties) {
        return new CloudJwtClientBeanDefinitionRegistryPostProcessorSupport(webClient, properties);
    }

}
