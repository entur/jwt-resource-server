package org.entur.jwt.spring.grpc.netty;

import org.entur.jwt.spring.grpc.DemoApplication;
import org.junit.jupiter.api.Test;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.grpc.server.security.AuthenticationProcessInterceptor;
import org.springframework.grpc.server.security.GrpcSecurity;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Spring Boot only creates a {@link GrpcSecurity} bean if there is a gRPC server. Without a gRPC server,
 * no authentication interceptor is needed, and the application must still start.
 */
public class NoGrpcServerApplicationTest {

    // not a @Configuration, so that it is not picked up by the component scan of the other tests
    @EnableAutoConfiguration
    static class NoGrpcServicesApplication {
    }

    private static ConfigurableApplicationContext run(Class<?> application, String... args) {
        return new SpringApplicationBuilder(application)
                .web(WebApplicationType.SERVLET)
                .properties(
                        "server.port=0",
                        "spring.grpc.server.port=0",
                        "entur.jwt.tenants.a.issuer=https://issuer.a",
                        "entur.jwt.tenants.a.jwk.location=http://localhost:1/jwks.json"
                )
                .run(args);
    }

    @Test
    public void testStartsWithGrpcServerDisabled() {
        try (ConfigurableApplicationContext context = run(DemoApplication.class, "--spring.grpc.server.enabled=false")) {
            assertThat(context.getBeanNamesForType(GrpcSecurity.class)).isEmpty();
            assertThat(context.getBeanNamesForType(AuthenticationProcessInterceptor.class)).isEmpty();
        }
    }

    @Test
    public void testStartsWithGrpcServerAndJwtDisabled() {
        try (ConfigurableApplicationContext context = run(DemoApplication.class, "--spring.grpc.server.enabled=false", "--entur.jwt.enabled=false")) {
            assertThat(context.getBeanNamesForType(AuthenticationProcessInterceptor.class)).isEmpty();
        }
    }

    @Test
    public void testStartsWithoutGrpcServices() {
        try (ConfigurableApplicationContext context = run(NoGrpcServicesApplication.class)) {
            assertThat(context.getBeanNamesForType(GrpcSecurity.class)).isEmpty();
            assertThat(context.getBeanNamesForType(AuthenticationProcessInterceptor.class)).isEmpty();
        }
    }
}
