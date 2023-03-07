package org.entur.jwt.spring.rest.config;

import org.springframework.context.annotation.Configuration;

@Configuration
public class TestConfiguration {

    /*
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

     */

}
