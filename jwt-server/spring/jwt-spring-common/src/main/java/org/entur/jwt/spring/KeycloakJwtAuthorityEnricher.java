package org.entur.jwt.spring;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Maps the roles of a single client in the Keycloak {@code resource_access} claim to authorities.
 * <br><br>
 * Keycloak (with the default 'full scope allowed') adds the roles of every client the user has roles in, so only the
 * roles of the configured client (normally this resource server) are mapped.
 */

public class KeycloakJwtAuthorityEnricher implements JwtAuthorityEnricher {

    private static Logger logger = LoggerFactory.getLogger(KeycloakJwtAuthorityEnricher.class);

    private final String clientId;

    private final AtomicBoolean warnedAboutMissingClientId = new AtomicBoolean();

    /**
     * Constructor
     *
     * @param clientId id of the client whose roles are mapped. If null or blank, no client roles are mapped.
     */

    public KeycloakJwtAuthorityEnricher(String clientId) {
        this.clientId = clientId == null || clientId.isBlank() ? null : clientId;
    }

    public String getClientId() {
        return clientId;
    }

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

        // note: this enricher sees the tokens of all tenants, so ignore claims which are not on the expected form
        Object resourceAccess = jwt.getClaim("resource_access");
        if (resourceAccess instanceof Map<?, ?> map) {
            if (clientId == null) {
                warnIfClientRoles(map);
                return;
            }

            Object value = map.get(clientId);
            if (value instanceof Map<?, ?> client) {
                Object rolesObject = client.get("roles");

                if (rolesObject instanceof List) {
                    List<?> roles = (List<?>) rolesObject;

                    for (Object role : roles) {
                        if (role instanceof String s) {
                            current.add(new SimpleGrantedAuthority(asRole(s)));
                        }
                    }
                } else if (rolesObject instanceof String[]) {
                    String[] roles = (String[]) rolesObject;

                    for (String role : roles) {
                        current.add(new SimpleGrantedAuthority(asRole(role)));
                    }
                } else if (rolesObject != null) {
                    logger.warn("Unable to map roles {} of type {} to an authority; expected List or array", rolesObject, rolesObject.getClass().getName());
                }
            }
        }
    }

    private void warnIfClientRoles(Map<?, ?> resourceAccess) {
        // warn (once) only if there are roles which would have been mapped, so that applications which
        // do not use client roles (or Keycloak) are not bothered
        if (warnedAboutMissingClientId.get()) {
            return;
        }
        for (Map.Entry<?, ?> entry : resourceAccess.entrySet()) {
            // skip account permissions
            // see
            // https://github.com/keycloak/keycloak/blob/master/adapters/oidc/adapter-core/src/main/java/org/keycloak/adapters/AdapterUtils.java#L39
            if ("account".equals(entry.getKey())) {
                continue;
            }
            if (entry.getValue() instanceof Map<?, ?> client && client.get("roles") != null) {
                if (warnedAboutMissingClientId.compareAndSet(false, true)) {
                    logger.warn("Ignoring client roles in the 'resource_access' claim, as no client id is configured. Set 'entur.jwt.flavours.keycloak.client-id' to map the roles of a client to authorities.");
                }
                return;
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
