package org.entur.jwt.spring;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.entur.jwt.spring.decode.ClosableJwtDecoders;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;

import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * The validators of the shared {@link ClosableJwtDecoders} bean: {@link OAuth2TokenValidator} beans are used in addition
 * to the {@link EnturJwtValidators}, and an {@link EnturJwtValidators} bean replaces the default validators.
 */
class EnturJwtValidatorsAutoConfigurationTest {

    private static final String ISSUER = "https://issuer.a";
    private static final String AUDIENCE = "https://my.audience";

    private static RSAKey key;

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(JwtAutoConfiguration.class))
            .withUserConfiguration(JwkSourceMapConfiguration.class)
            .withPropertyValues(
                    "entur.jwt.enabled=true",
                    "entur.jwt.tenants.a.issuer=" + ISSUER,
                    "entur.jwt.tenants.a.jwk.location=http://localhost:1/jwks.json",
                    "entur.jwt.claims.audiences=" + AUDIENCE
            );

    @Configuration
    static class JwkSourceMapConfiguration {

        @Bean
        public JwkSourceMap<SecurityContext> jwkSourceMap() {
            return new JwkSourceMap<>(Map.of(ISSUER, new ImmutableJWKSet<>(new JWKSet(key.toPublicJWK()))), Map.of());
        }
    }

    @Configuration
    static class ValidatorConfiguration {

        static final AtomicInteger VALIDATIONS = new AtomicInteger();

        @Bean
        public OAuth2TokenValidator<Jwt> customValidator() {
            return jwt -> {
                VALIDATIONS.incrementAndGet();
                return "rejected".equals(jwt.getSubject())
                        ? OAuth2TokenValidatorResult.failure(new OAuth2Error("invalid_token", "Rejected subject", null))
                        : OAuth2TokenValidatorResult.success();
            };
        }
    }

    @Configuration
    static class EnturJwtValidatorsConfiguration {

        @Bean
        public EnturJwtValidators customEnturJwtValidators() {
            return new EnturJwtValidators(List.of());
        }
    }

    @BeforeAll
    static void createKey() throws Exception {
        key = new RSAKeyGenerator(2048).keyID("a").generate();
    }

    private static String token(String audience, String subject, Date expirationTime) throws Exception {
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(ISSUER)
                .audience(audience)
                .subject(subject)
                .expirationTime(expirationTime)
                .build();
        SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(key.getKeyID()).build(), claims);
        jwt.sign(new RSASSASigner(key));
        return jwt.serialize();
    }

    private static Date inOneHour() {
        return new Date(System.currentTimeMillis() + 3_600_000);
    }

    @Test
    void testValidatorBeanIsUsedInAdditionToTheDefaultValidators() {
        runner.withUserConfiguration(ValidatorConfiguration.class).run(context -> {
            JwtDecoder decoder = context.getBean(ClosableJwtDecoders.class).getJwtDecoders().get(ISSUER);

            int validations = ValidatorConfiguration.VALIDATIONS.get();
            assertThat(decoder.decode(token(AUDIENCE, "subject", inOneHour())).getSubject()).isEqualTo("subject");
            assertThat(ValidatorConfiguration.VALIDATIONS.get()).isEqualTo(validations + 1);

            // default validators
            String wrongAudience = token("https://other.audience", "subject", inOneHour());
            assertThrows(JwtException.class, () -> decoder.decode(wrongAudience));
            String expired = token(AUDIENCE, "subject", new Date(System.currentTimeMillis() - 60_000));
            assertThrows(JwtException.class, () -> decoder.decode(expired));

            // custom validator
            String rejected = token(AUDIENCE, "rejected", inOneHour());
            assertThrows(JwtException.class, () -> decoder.decode(rejected));
        });
    }

    @Test
    void testCustomEnturJwtValidatorsReplaceTheDefaultValidators() {
        runner.withUserConfiguration(EnturJwtValidatorsConfiguration.class)
                .withPropertyValues("entur.jwt.claims.expires-at-leeway=120")
                .run(context -> {
                    assertThat(context).hasSingleBean(EnturJwtValidators.class);

                    JwtDecoder decoder = context.getBean(ClosableJwtDecoders.class).getJwtDecoders().get(ISSUER);

                    // no audience validation, and expiry still validated with the configured leeway
                    assertThat(decoder.decode(token("https://other.audience", "subject", new Date(System.currentTimeMillis() - 90_000))).getSubject()).isEqualTo("subject");

                    String expired = token("https://other.audience", "subject", new Date(System.currentTimeMillis() - 180_000));
                    assertThrows(JwtException.class, () -> decoder.decode(expired));
                });
    }
}
