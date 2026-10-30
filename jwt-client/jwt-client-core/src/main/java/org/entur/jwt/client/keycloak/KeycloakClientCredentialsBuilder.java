package org.entur.jwt.client.keycloak;

import org.entur.jwt.client.AbstractClientCredentialsBuilder;
import org.entur.jwt.client.ClientCredentials;

public class KeycloakClientCredentialsBuilder extends AbstractClientCredentialsBuilder<KeycloakClientCredentialsBuilder> {

    /**
     * Context path of Keycloak versions before 17. Later versions serve from the root path by default,
     * see the Keycloak <code>http-relative-path</code> option.
     */
    public static final String DEFAULT_CONTEXT_PATH = "/auth";

    private static final String TEMPLATE = "%s/realms/%s/protocol/openid-connect";
    private static final String ISSUE_TEMPLATE = TEMPLATE + "/token";
    private static final String REVOKE_TEMPLATE = TEMPLATE + "/logout";

    public static KeycloakClientCredentialsBuilder newInstance() {
        return new KeycloakClientCredentialsBuilder();
    }

    protected static String toPathPrefix(String contextPath) {
        // i.e. "/auth", "auth" or "/auth/" becomes "/auth", while null, "" or "/" becomes ""
        if (contextPath == null) {
            return "";
        }
        String path = contextPath.trim();
        while (path.endsWith("/")) {
            path = path.substring(0, path.length() - 1);
        }
        if (!path.isEmpty() && !path.startsWith("/")) {
            path = "/" + path;
        }
        return path;
    }

    protected String realm;
    protected String contextPath = DEFAULT_CONTEXT_PATH;

    @Override
    public ClientCredentials build() {
        if (realm == null) {
            throw new IllegalStateException("Expected realm");
        }
        String pathPrefix = toPathPrefix(contextPath);
        this.issuePath = String.format(ISSUE_TEMPLATE, pathPrefix, realm);
        this.refreshPath = issuePath;
        this.revokePath = String.format(REVOKE_TEMPLATE, pathPrefix, realm);

        return build(true); // keycloak supports using the basic authorization header
    }

    public KeycloakClientCredentialsBuilder withRealm(String tenant) {
        this.realm = tenant;
        return this;
    }

    public String getRealm() {
        return realm;
    }

    /**
     * Set the path Keycloak is served from. Defaults to {@value #DEFAULT_CONTEXT_PATH}; use <code>/</code>
     * for Keycloak 17 or later, unless it is configured with another <code>http-relative-path</code>.
     */
    public KeycloakClientCredentialsBuilder withContextPath(String contextPath) {
        this.contextPath = contextPath;
        return this;
    }

    public String getContextPath() {
        return contextPath;
    }
}
