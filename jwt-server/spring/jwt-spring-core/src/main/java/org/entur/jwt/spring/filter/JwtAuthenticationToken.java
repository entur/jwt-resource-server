package org.entur.jwt.spring.filter;

import java.io.Serializable;
import java.util.Collection;
import java.util.Map;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.SpringSecurityCoreVersion;

/**
 * Adapted copy of UsernamePasswordAuthentication.
 */

public class JwtAuthenticationToken extends AbstractAuthenticationToken {

    private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;

    private static final String CLAIM_SUBJECT = "sub";
    private static final String CLAIM_NAME = "name";

    // instead of principal we might have used the original token types here,
    // but for some of our reference libraries, these are not serializable classes
    // also this is more generic
    private final Map<String, Object> claims;
    private String credentials;

    public JwtAuthenticationToken(Map<String, Object> claims, String credentials, Collection<? extends GrantedAuthority> authorities, Object details) {
        super(authorities);
        if (!(claims instanceof Serializable)) {
            throw new IllegalArgumentException("Map of claims must be serializable");
        }
        this.claims = claims;
        this.credentials = credentials;
        super.setAuthenticated(true); // must use super, as we override
        super.setDetails(details);
    }

    public String getCredentials() {
        return this.credentials;
    }

    /**
     * 
     * Return principal as found in the subject (sub) claim
     * 
     * @return princial, or null
     */

    public String getPrincipal() {
        return (String) claims.get(CLAIM_SUBJECT);
    }

    /**
     * 
     * Return name as found in the claims, usually this will be null for an access-token.
     * 
     * @return name, or null
     */
    
    @Override
    public String getName() {
        return (String) claims.get(CLAIM_NAME);
    }
    
    @Override
    public void setAuthenticated(boolean isAuthenticated) {
        if (isAuthenticated) {
            throw new IllegalArgumentException("Cannot set this token to trusted - use constructor which takes a GrantedAuthority list instead");
        }

        super.setAuthenticated(false);
    }

    @Override
    public void eraseCredentials() {
        super.eraseCredentials();
        credentials = null;
    }

    @SuppressWarnings("unchecked")
    public <V> V getClaim(String name, Class<V> type) {
        Object object = claims.get(name);
        if (object != null) {
            if (type.isAssignableFrom(object.getClass())) {
                return (V) object;
            }
            throw new IllegalArgumentException("Expected claim '" + name + "' type " + type.getName() + ", found " + object.getClass().getName());
        }
        return null;
    }

    public Map<String, Object> getClaims() {
        return claims;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = super.hashCode();
        result = prime * result + ((credentials == null) ? 0 : credentials.hashCode());
        result = prime * result + ((claims == null) ? 0 : claims.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (!super.equals(obj))
            return false;
        if (getClass() != obj.getClass())
            return false;
        JwtAuthenticationToken other = (JwtAuthenticationToken) obj;
        if (credentials == null) {
            if (other.credentials != null)
                return false;
        } else if (!credentials.equals(other.credentials)) {
            return false;
        }
        if (claims == null) {
            if (other.claims != null)
                return false;
        } else if (!claims.equals(other.claims)) {
            return false;
        }
        return true;
    }

}
