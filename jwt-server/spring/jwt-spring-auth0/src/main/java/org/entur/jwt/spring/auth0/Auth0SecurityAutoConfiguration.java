package org.entur.jwt.spring.auth0;

import org.entur.jwt.spring.JwtAutoConfiguration;
import org.entur.jwt.spring.auth0.properties.Auth0AuthorityMapperProperties;
import org.entur.jwt.spring.auth0.properties.Auth0Properties;
import org.entur.jwt.spring.filter.JwtAuthorityMapper;
import org.entur.jwt.spring.filter.resolver.JwtArgumentResolver;
import org.entur.jwt.spring.filter.resolver.JwtPayload;
import org.entur.jwt.verifier.JwtClaimExtractor;
import org.entur.jwt.verifier.JwtVerifierFactory;
import org.entur.jwt.verifier.auth0.Auth0JwtClaimExtractor;
import org.entur.jwt.verifier.auth0.Auth0JwtVerifierFactory;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.auth0.jwt.interfaces.DecodedJWT;

@Configuration
@EnableConfigurationProperties(Auth0Properties.class)
@AutoConfigureBefore(value = JwtAutoConfiguration.class)
public class Auth0SecurityAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean(JwtClaimExtractor.class)
    @ConditionalOnProperty(name = "entur.jwt.enabled", havingValue = "true", matchIfMissing = false)
    public JwtClaimExtractor<DecodedJWT> jwtClaimExtractor(Auth0Properties properties) {
        return new Auth0JwtClaimExtractor(properties.getNamespace());
    }

    @Bean
    @ConditionalOnMissingBean(JwtVerifierFactory.class)
    @ConditionalOnProperty(name = "entur.jwt.enabled", havingValue = "true", matchIfMissing = false)
    public JwtVerifierFactory<DecodedJWT> jwtVerifierFactory(JwtClaimExtractor<DecodedJWT> extractor) {
        return new Auth0JwtVerifierFactory(extractor);
    }

    @Bean
    @ConditionalOnMissingBean(JwtAuthorityMapper.class)
    @ConditionalOnProperty(name = "entur.jwt.enabled", havingValue = "true", matchIfMissing = false)
    public JwtAuthorityMapper<DecodedJWT> jwtAuthorityMapper(Auth0Properties properties) {
        Auth0AuthorityMapperProperties authorityMapper = properties.getAuthorityMapper();
        return new Auth0JwtAuthorityMapper(authorityMapper.isAuth0(), authorityMapper.isKeycloak());
    }

    @Bean
    @ConditionalOnMissingBean(JwtArgumentResolver.class)
    @ConditionalOnProperty(name = "entur.jwt.enabled", havingValue = "true", matchIfMissing = false)
    public JwtArgumentResolver jwtArgumentResolver() {
        return new JwtArgumentResolver((value, type) -> new JwtPayload(value), JwtPayload.class);
    }

}
