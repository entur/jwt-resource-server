package org.entur.jwt.spring;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.Collection;
import java.util.List;
import java.util.Map;

public class KeycloakJwtAuthorityEnricher implements JwtAuthorityEnricher {

    private static Logger logger = LoggerFactory.getLogger(KeycloakJwtAuthorityEnricher.class);

    @Override
    public void enrich(Collection<GrantedAuthority> current, Jwt jwt) {
        // keycloak
        // https://usmanshahid.medium.com/levels-of-access-control-through-keycloak-part-3-access-control-through-roles-and-tokens-a1744c04895e

        //"resource_access": {
        //    "my-test-client": {
        //        "roles": [
        //        "my-new-client-role"
        //      ]
        //    },
        //    "account": {
        //        "roles": [
        //        "manage-account",
        //                "manage-account-links",
        //                "view-profile"
        //        ]
        //    }
        //}

        Object resourceAccess = jwt.getClaim("resource_access");
        if (resourceAccess != null) {
            Map<String, Object> map = (Map<String, Object>) resourceAccess;
            for (Map.Entry<String, Object> entry : map.entrySet()) {

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
                            current.add(new SimpleGrantedAuthority(asRole(role)));
                        }
                    } else if (rolesObject instanceof String[]) {
                        String[] roles = (String[]) rolesObject;

                        for (String role : roles) {
                            current.add(new SimpleGrantedAuthority(asRole(role)));
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
}
