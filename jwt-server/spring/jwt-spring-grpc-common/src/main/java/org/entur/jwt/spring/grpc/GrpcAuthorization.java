package org.entur.jwt.spring.grpc;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
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

    Authentication getAuthentication();

    default Object getPrincial() {
        Object object = getAuthentication();
        if (object instanceof JwtAuthenticationToken) {
            JwtAuthenticationToken authentication = (JwtAuthenticationToken) object;
            return authentication.getPrincipal();
        }
        return null;
    }

    default JwtAuthenticationToken getToken() {
        Object object = getAuthentication();
        if (object instanceof JwtAuthenticationToken) {
            return (JwtAuthenticationToken) object;
        }
        return null;
    }

    default void requireAnyAudience(String... audiences) {
        Set<String> set = new HashSet<>();
        Collections.addAll(set, audiences);

        requireAnyAudience(set);
    }

    default void requireAnyAudience(Collection<String> audiences) {
        requireAnyAudience(new HashSet<>(audiences));
    }

    default void requireAnyAudience(Set<String> audiences) {
        Object object = getAuthentication();
        if (object instanceof JwtAuthenticationToken t) {
            if (!hasAnyAudience(t, audiences)) {
                throw new AccessDeniedException("Not among required audiences.");
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
    default boolean hasAnyAudience(JwtAuthenticationToken authentication, Set<String> audiences) {
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

    default void requireAnyAuthority(String... authorities) {
        Object object = getAuthentication();
        if (object instanceof JwtAuthenticationToken) {
            JwtAuthenticationToken authentication = (JwtAuthenticationToken) object;

            if (!hasAnyAuthority(authentication, authorities)) {
                throw new AccessDeniedException("");
            }
        }
        throw new AuthenticationCredentialsNotFoundException("");
    }

    default boolean hasAnyAuthority(JwtAuthenticationToken authentication, String... authorities) {
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

    default void requireAllAuthorities(Collection<String> authorities) {
        requireAllAuthorities(new HashSet<>(authorities));
    }

    default void requireAllAuthorities(String... authorities) {
        Set<String> set = new HashSet<>();
        Collections.addAll(set, authorities);
        requireAllAuthorities(set);
    }

    default void requireAllAuthorities(Set<String> authorities) {
        Object object = getAuthentication();
        if (object instanceof JwtAuthenticationToken) {
            if (hasAllAuthorities((JwtAuthenticationToken) object, authorities)) {
                return;
            }
            throw new AccessDeniedException("");
        }

        throw new AuthenticationCredentialsNotFoundException("");
    }

    default boolean hasAllAuthorities(JwtAuthenticationToken authentication, Set<String> authorities) {
        Set<String> grantedAuthorities = authentication.getAuthorities().stream().map(a -> a.getAuthority()).collect(Collectors.toSet());
        return grantedAuthorities.containsAll(authorities);
    }

}
