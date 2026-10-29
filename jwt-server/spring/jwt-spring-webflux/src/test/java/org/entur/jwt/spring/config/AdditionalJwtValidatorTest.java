package org.entur.jwt.spring.config;

import org.entur.jwt.junit5.AccessToken;
import org.entur.jwt.junit5.AuthorizationServer;
import org.entur.jwt.junit5.claim.ExpiresAt;
import org.entur.jwt.junit5.claim.IssuedAt;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.webtestclient.autoconfigure.AutoConfigureWebTestClient;
import org.springframework.context.annotation.Bean;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.reactive.server.WebTestClient;

import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;

/**
 * An {@link OAuth2TokenValidator} bean is used in addition to (not instead of) the default validators.
 */
@AuthorizationServer
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureWebTestClient
@TestPropertySource(properties = {"entur.jwt.claims.audiences=mock.my.audience"})
public class AdditionalJwtValidatorTest {

    static final AtomicInteger VALIDATIONS = new AtomicInteger();

    @TestConfiguration
    static class ValidatorConfiguration {

        @Bean
        public OAuth2TokenValidator<Jwt> countingValidator() {
            return jwt -> {
                VALIDATIONS.incrementAndGet();
                return OAuth2TokenValidatorResult.success();
            };
        }
    }

    @Autowired
    private WebTestClient webTestClient;

    @Test
    public void testValidatorBeanIsUsed(@AccessToken(audience = "mock.my.audience") String token) {
        int validations = VALIDATIONS.get();

        webTestClient
                .get()
                .uri("/protected")
                .header(AUTHORIZATION, token)
                .exchange()
                .expectStatus().is2xxSuccessful();

        assertThat(VALIDATIONS.get()).isEqualTo(validations + 1);
    }

    @Test
    public void testExpiredTokenIsRejected(@AccessToken(audience = "mock.my.audience") @IssuedAt(-7200) @ExpiresAt(-3600) String token) {
        webTestClient
                .get()
                .uri("/protected")
                .header(AUTHORIZATION, token)
                .exchange()
                .expectStatus().isUnauthorized();
    }

    @Test
    public void testWrongAudienceIsRejected(@AccessToken(audience = "other.audience") String token) {
        webTestClient
                .get()
                .uri("/protected")
                .header(AUTHORIZATION, token)
                .exchange()
                .expectStatus().isUnauthorized();
    }
}
