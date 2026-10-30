package org.entur.jwt.spring.grpc.netty;

import org.entur.jwt.spring.grpc.DemoApplication;
import org.junit.jupiter.api.Test;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.builder.SpringApplicationBuilder;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * In a gRPC application, startup fails if there are tenants but no audiences, as tokens issued for other APIs would then be accepted.
 */
public class RequiredAudiencesApplicationTest {

    @Test
    public void testFailsWithoutAudiences() {
        SpringApplicationBuilder application = new SpringApplicationBuilder(DemoApplication.class)
                .web(WebApplicationType.SERVLET)
                .properties(
                        "server.port=0",
                        "spring.grpc.server.port=0",
                        "entur.jwt.tenants.a.issuer=https://issuer.a",
                        "entur.jwt.tenants.a.jwk.location=http://localhost:1/jwks.json"
                );

        // overrides the audiences of application.yaml
        assertThatThrownBy(() -> application.run("--entur.jwt.claims.audiences=").close())
                .hasStackTraceContaining("No audiences configured for tenants [a]")
                .hasStackTraceContaining("entur.jwt.claims.audiences");
    }
}
