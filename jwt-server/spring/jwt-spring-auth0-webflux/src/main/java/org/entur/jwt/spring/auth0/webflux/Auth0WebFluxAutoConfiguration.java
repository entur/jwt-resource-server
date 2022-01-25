package org.entur.jwt.spring.auth0.webflux;

import org.entur.jwt.spring.JwtAutoConfiguration;
import org.entur.jwt.spring.auth0.Auth0AutoConfiguration;
import org.entur.jwt.spring.auth0.properties.Auth0Properties;
import org.entur.jwt.spring.filter.resolver.JwtArgumentResolver;
import org.entur.jwt.spring.filter.resolver.JwtPayload;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@EnableConfigurationProperties(Auth0Properties.class)
@AutoConfigureAfter(value = Auth0AutoConfiguration.class)
@AutoConfigureBefore(value = JwtAutoConfiguration.class)
public class Auth0WebFluxAutoConfiguration extends Auth0AutoConfiguration {

    @Bean
    @ConditionalOnMissingBean(JwtArgumentResolver.class)
    @ConditionalOnProperty(name = "entur.jwt.enabled", havingValue = "true")
    public JwtArgumentResolver jwtArgumentResolver() {
        return new JwtArgumentResolver((value, type) -> new JwtPayload(value), JwtPayload.class);
    }

}
