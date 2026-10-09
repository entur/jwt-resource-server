package org.entur.jwt.spring.grpc.netty;

import org.entur.jwt.junit5.AccessToken;
import org.entur.jwt.junit5.AuthorizationServer;
import org.entur.jwt.spring.JwkSourceMap;
import org.entur.jwt.spring.decode.ClosableJwtDecoders;
import org.entur.jwt.spring.decode.ClosableJwtDecodersBuilder;
import org.entur.jwt.spring.grpc.AbstractGrpcTest;
import org.entur.jwt.spring.grpc.test.GreetingResponse;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.annotation.DirtiesContext;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * A custom {@link ClosableJwtDecoders} bean (the documented way to customize JWT decoding) is used for gRPC calls.
 */
@AuthorizationServer
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@DirtiesContext
public class CustomClosableJwtDecodersContextTest extends AbstractGrpcTest {

    static final AtomicInteger DECODES = new AtomicInteger();

    @TestConfiguration
    static class CustomDecodersConfiguration {

        @Bean
        public ClosableJwtDecoders customClosableJwtDecoders(JwkSourceMap jwkSourceMap, List<OAuth2TokenValidator<Jwt>> jwtValidators) {
            ClosableJwtDecoders decoders = new ClosableJwtDecodersBuilder()
                    .withJwkSources(jwkSourceMap.getJwkSources())
                    .withJwtValidators(jwtValidators)
                    .build();

            // count decodes
            Map<String, JwtDecoder> counting = new HashMap<>();
            for (Map.Entry<String, JwtDecoder> entry : decoders.getJwtDecoders().entrySet()) {
                JwtDecoder delegate = entry.getValue();
                counting.put(entry.getKey(), token -> {
                    DECODES.incrementAndGet();
                    return delegate.decode(token);
                });
            }
            return new ClosableJwtDecoders(counting);
        }
    }

    @Autowired
    private ApplicationContext context;

    @Test
    public void testCustomDecodersAreUsed(@AccessToken(audience = "https://my.audience") String token) {
        assertThat(context.getBeansOfType(ClosableJwtDecoders.class)).containsOnlyKeys("customClosableJwtDecoders");

        int decodes = DECODES.get();

        GreetingResponse response = stub(token).protectedWithPartnerTenant(greetingRequest);

        assertThat(response.getMessage()).isNotEmpty();
        assertThat(DECODES.get()).isEqualTo(decodes + 1);
    }
}
