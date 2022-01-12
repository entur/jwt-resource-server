package org.entur.jwt.spring.auth0;

import org.entur.jwt.spring.Auth0SecurityAutoConfiguration;
import org.entur.jwt.spring.JwtAutoConfigurationWeb;
import org.entur.jwt.spring.filter.resolver.JwtArgumentResolver;
import org.entur.jwt.spring.filter.resolver.JwtPayload;
import org.entur.jwt.spring.properties.Auth0Properties;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@EnableConfigurationProperties(Auth0Properties.class)
@AutoConfigureBefore(value = JwtAutoConfigurationWeb.class)
public class Auth0SecurityAutoConfigurationWeb extends Auth0SecurityAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean(JwtArgumentResolver.class)
    @ConditionalOnProperty(name = "entur.jwt.enabled", havingValue = "true")
    public JwtArgumentResolver jwtArgumentResolver() {
        return new JwtArgumentResolver((value, type) -> new JwtPayload(value), JwtPayload.class);
    }

}
