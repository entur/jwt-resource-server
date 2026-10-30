package org.entur.jwt.spring.grpc.netty;

import org.entur.jwt.spring.grpc.DemoApplication;
import org.junit.jupiter.api.Test;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.builder.SpringApplicationBuilder;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Servlet gRPC (enabled by Spring Boot when the gRPC servlet is on the classpath) is not supported,
 * as there would be no authentication interceptor, so startup fails.
 */
public class GrpcServletServerGuardApplicationTest {

    private static void run(String... args) {
        new SpringApplicationBuilder(DemoApplication.class)
                .web(WebApplicationType.SERVLET)
                .properties(
                        "server.port=0",
                        "server.http2.enabled=true",
                        "entur.jwt.tenants.a.issuer=https://issuer.a",
                        "entur.jwt.tenants.a.jwk.location=http://localhost:1/jwks.json"
                )
                .run(args)
                .close();
    }

    @Test
    public void testFailsWithServletGrpcServer() {
        // overrides application.yaml
        assertThatThrownBy(() -> run("--spring.grpc.server.servlet.enabled=true"))
                .hasStackTraceContaining("Servlet gRPC not supported by this module");
    }

    @Test
    public void testFailsWithServletGrpcServerWithoutJwt() {
        // authorization is still enabled
        assertThatThrownBy(() -> run("--spring.grpc.server.servlet.enabled=true", "--entur.jwt.enabled=false"))
                .hasStackTraceContaining("Servlet gRPC not supported by this module");
    }
}
