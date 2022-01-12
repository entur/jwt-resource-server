package org.entur.jwt.spring.reactive.auth0;

import org.entur.jwt.spring.Auth0SecurityAutoConfiguration;
import org.entur.jwt.spring.JwtAutoConfigurationWebFlux;
import org.entur.jwt.spring.filter.JwtAuthenticationManager;
import org.entur.jwt.spring.filter.resolver.JwtArgumentResolver;
import org.entur.jwt.spring.filter.resolver.JwtPayload;
import org.entur.jwt.spring.properties.Auth0Properties;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.ReactiveAuthenticationManager;

@Configuration
@EnableConfigurationProperties(Auth0Properties.class)
@AutoConfigureBefore(value = JwtAutoConfigurationWebFlux.class)
public class Auth0SecurityAutoConfigurationWebFlux extends Auth0SecurityAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean(JwtArgumentResolver.class)
    @ConditionalOnProperty(name = "entur.jwt.enabled", havingValue = "true")
    public JwtArgumentResolver jwtArgumentResolver() {
        return new JwtArgumentResolver((value, type) -> new JwtPayload(value), JwtPayload.class);
    }

    @Bean
    @ConditionalOnMissingBean(ReactiveAuthenticationManager.class)
    @ConditionalOnProperty(name = "entur.jwt.enabled", havingValue = "true")
    public ReactiveAuthenticationManager reactiveAuthenticationManager() {
        return new JwtAuthenticationManager();
    }

}
