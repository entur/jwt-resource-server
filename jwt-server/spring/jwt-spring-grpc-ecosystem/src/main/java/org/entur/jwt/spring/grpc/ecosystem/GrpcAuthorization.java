package org.entur.jwt.spring.grpc.ecosystem;

import net.devh.boot.grpc.server.security.interceptors.AuthenticatingServerInterceptor;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Helper class for manual authorization checking.
 */

public interface GrpcAuthorization {

    public default Object getPrincial() {
        SecurityContext securityContext = AuthenticatingServerInterceptor.SECURITY_CONTEXT_KEY.get();
        if(securityContext != null) {
            Authentication authentication = securityContext.getAuthentication();
            if (authentication instanceof JwtAuthenticationToken jwtAuthenticationToken) {
                return authentication.getPrincipal();
            }
        }
        return null;
    }

    public default JwtAuthenticationToken getToken() {
        SecurityContext securityContext = AuthenticatingServerInterceptor.SECURITY_CONTEXT_KEY.get();
        if(securityContext != null) {
            Authentication authentication = securityContext.getAuthentication();
            if (authentication instanceof JwtAuthenticationToken jwtAuthenticationToken) {
                return jwtAuthenticationToken;
            }
        }
        return null;
    }

    public default void requireAnyAudience(String... audiences) {
        Set<String> set = new HashSet<>();
        Collections.addAll(set, audiences);

        requireAnyAudience(set);
    }

    public default void requireAnyAudience(Collection<String> audiences) {
        requireAnyAudience(new HashSet<>(audiences));
    }

    public default void requireAnyAudience(Set<String> audiences) {
        SecurityContext securityContext = AuthenticatingServerInterceptor.SECURITY_CONTEXT_KEY.get();
        if(securityContext != null) {
            Authentication authentication = securityContext.getAuthentication();
            if (authentication instanceof JwtAuthenticationToken jwtAuthenticationToken) {
                if (!hasAnyAudience(jwtAuthenticationToken, audiences)) {
                    throw new AccessDeniedException("Not amoung required audiences.");
                }
            }
            // at least one of the required audiences was found
        } else {
            throw new AuthenticationCredentialsNotFoundException("");
        }
    }

    public default boolean hasAnyAudience(JwtAuthenticationToken authentication, Collection<String> audiences) {
        return hasAnyAudience(authentication, new HashSet<>(audiences));
    }

    @SuppressWarnings("unchecked")
    public default boolean hasAnyAudience(JwtAuthenticationToken authentication, Set<String> audiences) {
        Map<String, Object> tokenAttributes = authentication.getTokenAttributes();

        Object claim = tokenAttributes.get("aud");

        if (claim == null) {
            throw new IllegalArgumentException("Expected audience");
        }

        List<String> jwtAudiences;
        if (claim instanceof List) {
            jwtAudiences = (List<String>) claim;
        } else if (claim instanceof String) {
            jwtAudiences = Arrays.asList((String) claim);
        } else if (claim instanceof String[]) {
            jwtAudiences = Arrays.asList((String[]) claim);
        } else throw new IllegalArgumentException("Unexpected claim type " + claim.getClass().getName());

        return jwtAudiences != null && !Collections.disjoint(audiences, jwtAudiences);
    }

    public default void requireAnyAuthority(String... authorities) {
        SecurityContext securityContext = AuthenticatingServerInterceptor.SECURITY_CONTEXT_KEY.get();
        if(securityContext != null) {
            Authentication authentication = securityContext.getAuthentication();
            if (authentication instanceof JwtAuthenticationToken jwtAuthenticationToken) {
                if (!hasAnyAuthority(jwtAuthenticationToken, authorities)) {
                    throw new AccessDeniedException("");
                }
            }
        }
        throw new AuthenticationCredentialsNotFoundException("");
    }

    public default boolean hasAnyAuthority(JwtAuthenticationToken authentication, String... authorities) {
        Collection<GrantedAuthority> grantedAuthorities = authentication.getAuthorities();
        for (GrantedAuthority grantedAuthority : grantedAuthorities) {
            for (String string : authorities) {
                if (grantedAuthority.getAuthority().equals(string)) {
                    return true;
                }
            }
        }
        return false;
    }

    public default void requireAllAuthorities(Collection<String> authorities) {
        requireAllAuthorities(new HashSet<>(authorities));
    }

    public default void requireAllAuthorities(String... authorities) {
        Set<String> set = new HashSet<>();
        Collections.addAll(set, authorities);
        requireAllAuthorities(set);
    }

    public default void requireAllAuthorities(Set<String> authorities) {
        SecurityContext securityContext = AuthenticatingServerInterceptor.SECURITY_CONTEXT_KEY.get();
        if(securityContext != null) {
            Authentication authentication = securityContext.getAuthentication();
            if (authentication instanceof JwtAuthenticationToken jwtAuthenticationToken) {
                if (hasAllAuthorities(jwtAuthenticationToken, authorities)) {
                    return;
                }
            }
            throw new AccessDeniedException("");
        }

        throw new AuthenticationCredentialsNotFoundException("");
    }

    public default boolean hasAllAuthorities(JwtAuthenticationToken authentication, Set<String> authorities) {
        Set<String> grantedAuthorities = authentication.getAuthorities().stream().map(a -> a.getAuthority()).collect(Collectors.toSet());
        return grantedAuthorities.containsAll(authorities);
    }

}
