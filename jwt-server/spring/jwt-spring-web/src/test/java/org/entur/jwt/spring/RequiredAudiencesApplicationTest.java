package org.entur.jwt.spring;

import org.junit.jupiter.api.Test;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.context.ConfigurableApplicationContext;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Startup fails if there are tenants but no audiences, as tokens issued for other APIs would then be accepted.
 */
public class RequiredAudiencesApplicationTest {

    private static SpringApplicationBuilder application() {
        return new SpringApplicationBuilder(DemoApplication.class)
                .web(WebApplicationType.SERVLET)
                .properties(
                        "server.port=0",
                        "entur.jwt.tenants.a.issuer=https://issuer.a",
                        "entur.jwt.tenants.a.jwk.location=http://localhost:1/jwks.json"
                );
    }

    @Test
    public void testFailsWithoutAudiences() {
        // overrides the audiences of application.yaml
        assertThatThrownBy(() -> application().run("--entur.jwt.claims.audiences=").close())
                .hasStackTraceContaining("No audiences configured for tenants [a]")
                .hasStackTraceContaining("entur.jwt.claims.audiences");
    }

    @Test
    public void testStartsWithAudiences() {
        try (ConfigurableApplicationContext context = application().run()) {
            assertThat(context.isActive()).isTrue();
        }
    }
}
