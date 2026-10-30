package org.entur.jwt.spring.grpc.netty;

import org.entur.jwt.spring.grpc.DemoApplication;
import org.junit.jupiter.api.Test;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.context.ConfigurableApplicationContext;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * In a gRPC application (with all its auto-configuration), a JwtDecoder bean created by Spring Boot from its
 * resource server properties would be ignored, so startup fails; it starts when the check is disabled.
 */
public class JwtDecoderBeanGuardApplicationTest {

    private static SpringApplicationBuilder application(String... properties) {
        return new SpringApplicationBuilder(DemoApplication.class)
                .web(WebApplicationType.SERVLET)
                .properties(
                        "server.port=0",
                        "spring.grpc.server.port=0",
                        "entur.jwt.tenants.a.issuer=https://issuer.a",
                        "entur.jwt.tenants.a.jwk.location=http://localhost:1/jwks.json",
                        "spring.security.oauth2.resourceserver.jwt.jwk-set-uri=http://localhost:1/jwks.json"
                )
                .properties(properties);
    }

    @Test
    public void testFailsWithSpringBootResourceServerJwtDecoderWhenEnabled() {
        assertThatThrownBy(() -> application("entur.jwt.decode.fail-on-jwt-decoder-bean=true").run().close())
                .hasStackTraceContaining("spring.security.oauth2.resourceserver.jwt")
                .hasStackTraceContaining("entur.jwt.decode.fail-on-jwt-decoder-bean=true");
    }

    @Test
    public void testStartsByDefault() {
        try (ConfigurableApplicationContext context = application().run()) {
            assertThat(context.isActive()).isTrue();
        }
    }
}
