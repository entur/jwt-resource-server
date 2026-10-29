package org.entur.jwt.spring.config;

import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import org.entur.jwt.spring.filter.log.JwtMappedDiagnosticContextMapper;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.slf4j.MDC;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

public class JwtMappedDiagnosticContextFilterTest {

    private final Jwt jwt = Jwt.withTokenValue("token")
            .header("alg", "RS256")
            .claim("iss", "https://my.issuer")
            .issuedAt(Instant.now())
            .expiresAt(Instant.now().plusSeconds(60))
            .build();

    @AfterEach
    public void clear() {
        SecurityContextHolder.clearContext();
        MDC.clear();
    }

    @Test
    public void testContextIsRemovedAfterRequest() throws Exception {
        SecurityContextHolder.getContext().setAuthentication(new JwtAuthenticationToken(jwt));

        Map<String, String> duringRequest = new HashMap<>();
        MockFilterChain chain = new MockFilterChain() {
            @Override
            public void doFilter(ServletRequest request, ServletResponse response) {
                duringRequest.put("issuer", MDC.get("issuer"));
            }
        };

        new JwtMappedDiagnosticContextFilter(new IssuerMapper(false)).doFilter(new MockHttpServletRequest(), new MockHttpServletResponse(), chain);

        assertThat(duringRequest).containsEntry("issuer", "https://my.issuer");
        assertThat(MDC.get("issuer")).isNull();
    }

    @Test
    public void testContextIsRemovedIfAddingContextFails() {
        SecurityContextHolder.getContext().setAuthentication(new JwtAuthenticationToken(jwt));

        JwtMappedDiagnosticContextFilter filter = new JwtMappedDiagnosticContextFilter(new IssuerMapper(true));

        assertThatThrownBy(() -> filter.doFilter(new MockHttpServletRequest(), new MockHttpServletResponse(), new MockFilterChain()))
                .isInstanceOf(IllegalStateException.class);

        // i.e. not leaked to the next request handled by this thread
        assertThat(MDC.get("issuer")).isNull();
    }

    /**
     * Adds the issuer, then optionally fails (like for a claim which cannot be mapped).
     */
    private static class IssuerMapper implements JwtMappedDiagnosticContextMapper {

        private final boolean fail;

        private IssuerMapper(boolean fail) {
            this.fail = fail;
        }

        @Override
        public Map<String, String> getContext(Jwt token) {
            return Map.of("issuer", token.getClaim("iss"));
        }

        @Override
        public void addContext(Jwt token) {
            MDC.put("issuer", token.getClaim("iss"));
            if (fail) {
                throw new IllegalStateException("Simulated failure");
            }
        }

        @Override
        public void removeContext(Jwt token) {
            MDC.remove("issuer");
        }
    }
}
