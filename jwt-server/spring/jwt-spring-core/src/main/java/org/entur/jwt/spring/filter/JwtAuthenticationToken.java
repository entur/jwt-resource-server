package org.entur.jwt.spring.filter;

import java.util.Collection;
import java.util.Map;

import org.entur.jwt.verifier.JwtClaimException;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.SpringSecurityCoreVersion;


/**
 * Adapted copy of UsernamePasswordAuthentication.
 */

public class JwtAuthenticationToken extends AbstractAuthenticationToken {

    private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;

    // instead of principal we might have used the original token types here,
    // but for some of our reference libraries, these are not serializable classes
    // also this is more generic
    private final Map<String, Object> principal;
    private String credentials;
    
    public JwtAuthenticationToken(Map<String, Object> principal, String credentials, Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.principal = principal;
        this.credentials = credentials;
        super.setAuthenticated(true); // must use super, as we override
    }

	public String getCredentials() {
        return this.credentials;
    }

    public Map<String, Object> getPrincipal() {
        return this.principal;
    }

    public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
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
	public <V> V getClaim(String name, Class<V> type) throws JwtClaimException {
    	return (V) principal.get(name);
    }
    
    public Map<String, Object> getClaims() {
    	return principal;
    }

}
