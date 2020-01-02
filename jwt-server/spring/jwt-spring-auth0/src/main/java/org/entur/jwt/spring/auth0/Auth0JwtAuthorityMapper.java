package org.entur.jwt.spring.auth0;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import org.entur.jwt.spring.filter.JwtAuthorityMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import com.auth0.jwt.impl.NullClaim;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;

public class Auth0JwtAuthorityMapper implements JwtAuthorityMapper<DecodedJWT> {

    protected static final Logger logger = LoggerFactory.getLogger(Auth0JwtAuthorityMapper.class);

    protected final boolean extractAuth0Permissions;
    protected final boolean extractKeycloakResourceAccess;

    public Auth0JwtAuthorityMapper(boolean auth0Permissions, boolean keycloakResourceAccess) {
        this.extractAuth0Permissions = auth0Permissions;
        this.extractKeycloakResourceAccess = keycloakResourceAccess;
    }

    @Override
    public List<GrantedAuthority> getGrantedAuthorities(DecodedJWT token) {

        List<GrantedAuthority> authorities = new ArrayList<>();

        if (!extractKeycloakResourceAccess && !extractAuth0Permissions) {
            addScope(token, authorities);
        }

        if (extractAuth0Permissions) {
            addPermissions(token, authorities);
        }

        if (extractKeycloakResourceAccess) {
            addResourceAccess(token, authorities);
        }
        return authorities;
    }

    @SuppressWarnings({ "unchecked", "rawtypes" })
    private void addResourceAccess(DecodedJWT token, List<GrantedAuthority> authorities) {
        // keycloak

        /*
         * "resource_access": { "e8e9a643-fb78-467e-9d9f-d14da69c6870": { "roles": [
         * "uma_protection" ] }, "account": { "roles": [ "manage-account",
         * "manage-account-links", "view-profile" ] } },
         */
        Claim resourceAccess = token.getClaim("resource_access");
        if (resourceAccess != null && !(resourceAccess instanceof NullClaim)) {
            Map<String, Object> map = resourceAccess.asMap();
            for (Entry<String, Object> entry : map.entrySet()) {

                // skip account permissions
                // see
                // https://github.com/keycloak/keycloak/blob/master/adapters/oidc/adapter-core/src/main/java/org/keycloak/adapters/AdapterUtils.java#L39
                if (entry.getKey().equals("account")) {
                    continue;
                }
                Object value = entry.getValue();

                if (value instanceof Map) {
                    Object rolesObject = ((Map) value).get("roles");

                    if (rolesObject instanceof List) {
                        List<String> roles = (List<String>) rolesObject;

                        for (String role : roles) {
                            authorities.add(new SimpleGrantedAuthority(asRole(role)));
                        }
                    } else if (rolesObject instanceof String[]) {
                        String[] roles = (String[]) rolesObject;

                        for (String role : roles) {
                            authorities.add(new SimpleGrantedAuthority(asRole(role)));
                        }
                    } else {
                        logger.warn("Unable to map roles {} of type {} to an authority; expected List or array", rolesObject, rolesObject.getClass().getName());
                    }
                }
            }
        }
    }

    protected String asRole(String role) {
        if (role.startsWith("ROLE_")) {
            return role;
        }
        return "ROLE_" + role;
    }

    protected void addScope(DecodedJWT token, List<GrantedAuthority> authorities) {
        Claim scopeClaim = token.getClaim("scope");
        if (scopeClaim != null && !(scopeClaim instanceof NullClaim)) {
            String[] scopes = scopeClaim.asString().split("\\s");
            for (String scope : scopes) {
                authorities.add(new SimpleGrantedAuthority(asScope(scope)));
            }
        }
    }

    protected String asScope(String scope) {
        if (scope.startsWith("SCOPE_")) {
            return scope;
        }
        return "SCOPE_" + scope;
    }

    private void addPermissions(DecodedJWT token, List<GrantedAuthority> authorities) {
        Claim permissionClaim = token.getClaim("permissions");
        if (permissionClaim != null && !(permissionClaim instanceof NullClaim)) {
            String[] permissions = permissionClaim.asArray(String.class);
            for (String permission : permissions) {
                authorities.add(new SimpleGrantedAuthority(asPermission(permission)));
            }
        }
    }

    protected String asPermission(String permission) {
        return permission;
    }

}
