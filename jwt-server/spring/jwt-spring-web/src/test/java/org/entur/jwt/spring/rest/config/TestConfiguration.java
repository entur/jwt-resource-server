package org.entur.jwt.spring.rest.config;

import java.util.Map;
import java.util.function.BiFunction;

import org.entur.jwt.spring.filter.resolver.JwtArgumentResolver;
import org.entur.jwt.verifier.JwtClaimExtractor;
import org.entur.jwt.verifier.JwtVerifierFactory;
import org.entur.jwt.verifier.auth0.Auth0JwtClaimExtractor;
import org.entur.jwt.verifier.auth0.Auth0JwtVerifierFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.auth0.jwt.interfaces.DecodedJWT;

@Configuration
public class TestConfiguration {

    @Bean
    @ConditionalOnMissingBean(JwtClaimExtractor.class)
    public JwtClaimExtractor<DecodedJWT> jwtClaimExtractor() {
        return new Auth0JwtClaimExtractor("");
    }

    @Bean
    @ConditionalOnMissingBean(JwtVerifierFactory.class)
    public JwtVerifierFactory<DecodedJWT> jwtVerifierFactory(JwtClaimExtractor<DecodedJWT> extractor) {
        return new Auth0JwtVerifierFactory(extractor);
    }

    @Bean
    @ConditionalOnMissingBean(JwtAuthorityMapper.class)
    public JwtAuthorityMapper<DecodedJWT> jwtAuthorityMapper() {
        return new SimpleJwtAuthorityMapper();
    }

    @Bean
    @ConditionalOnMissingBean(JwtArgumentResolver.class)
    public JwtArgumentResolver jwtArgumentResolver() {
        BiFunction<Map<String, Object>, Class<?>, ?> a = new TenantArgumentResolver();
        return new JwtArgumentResolver(a, Tenant.class, PartnerTenant.class);
    }

}
