package org.entur.jwt.spring.grpc;

import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.Closeable;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.entur.jwt.spring.filter.JwtAuthenticationToken;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import io.grpc.Context;

public class GrpcAuthorizationTest implements GrpcAuthorization {
    
    private JwtAuthenticationToken jwtAuthenticationToken;

    private static class ContextWrapper implements Closeable {

        private Context rootContext = Context.current();
        private Context context;

        public ContextWrapper(JwtAuthenticationToken jwtAuthenticationToken) {
            Context current = Context.current();
            context = current.withValue(GrpcAuthorization.SECURITY_CONTEXT_AUTHENTICATION, jwtAuthenticationToken);
            context.attach();
        }

        @Override
        public void close() {
            context.detach(rootContext);
        }
    }

    @BeforeEach
    public void before() {
        String credentials = "Bearer x.y.z";
        Map<String, Object> claims = new HashMap<>();
        claims.put("aud", Arrays.asList("http://entur.org"));
        
        List<GrantedAuthority> authorities = new ArrayList<>();
        authorities.add(new SimpleGrantedAuthority("read"));
        authorities.add(new SimpleGrantedAuthority("modify"));
        
        jwtAuthenticationToken = new JwtAuthenticationToken(claims, credentials, authorities, "principal", "deails");

    }

    @Test
    public void testNoAuthorization() {
        assertThrows(AuthenticationCredentialsNotFoundException.class, () -> {
            requireAllAuthorities("read");
        });        
    }

    
    @Test
    public void testInsufficientAuthorization() {
        try (ContextWrapper a = new ContextWrapper(jwtAuthenticationToken)) {
            assertThrows(AccessDeniedException.class, () -> {
                requireAllAuthorities("delete");
            });
            assertThrows(AccessDeniedException.class, () -> {
                requireAllAuthorities("delete");
            });        
        }
    }

    @Test
    public void testSufficientAuthorization() {
        try (ContextWrapper a = new ContextWrapper(jwtAuthenticationToken)) {
            requireAllAuthorities("read");
            requireAllAuthorities("read", "modify");
        }
    }

}
