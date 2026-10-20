package org.entur.jwt.spring.decode.cache;

import org.entur.jwt.spring.JwtAutoConfiguration;
import org.entur.jwt.spring.decode.ClosableJwtDecoders;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The decoded JWT cache as part of the shared {@link ClosableJwtDecoders} bean, see {@link org.entur.jwt.spring.decode.ClosableJwtDecodersAutoConfigurationTest}.
 */
class DecodedJwtCacheAutoConfigurationTest {

    private static final String ISSUER = "https://issuer.a";

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(JwtAutoConfiguration.class))
            .withPropertyValues(
                    "entur.jwt.enabled=true",
                    "entur.jwt.tenants.a.issuer=" + ISSUER,
                    "entur.jwt.tenants.a.jwk.location=http://localhost:1/jwks.json",
                    "entur.jwt.tenants.a.decoder-cache.enabled=true",
                    "entur.jwt.jwk.cache.preemptive.eager.enabled=true"
            );

    @Test
    void testDecodersAreClosedWithTheContext() {
        AtomicReference<DecodedJwtCacheJwtDecoder> decoder = new AtomicReference<>();

        runner.run(context -> {
            ClosableJwtDecoders decoders = context.getBean(ClosableJwtDecoders.class);
            decoder.set((DecodedJwtCacheJwtDecoder) decoders.getJwtDecoders().get(ISSUER));

            // the default cleanup interval schedules a background thread
            assertThat(decoder.get().scheduledExecutorService.isShutdown()).isFalse();
        });

        // context closed
        assertThat(decoder.get().scheduledExecutorService.isShutdown()).isTrue();
    }
}
