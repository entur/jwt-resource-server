package org.entur.jwt.spring.grpc.lognet;

import org.entur.jwt.spring.grpc.GrpcAuthorization;
import org.lognet.springboot.grpc.security.GrpcSecurity;
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

public interface LognetGrpcAuthorization extends GrpcAuthorization {

    default Authentication getAuthentication() {
        return GrpcSecurity.AUTHENTICATION_CONTEXT_KEY.get();
    }

}
