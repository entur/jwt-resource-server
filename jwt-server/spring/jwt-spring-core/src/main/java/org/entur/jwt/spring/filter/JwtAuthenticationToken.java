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
    	return (V) principal.get(name);
    }
    
    public Map<String, Object> getClaims() {
    	return principal;
    }

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = super.hashCode();
		result = prime * result + ((credentials == null) ? 0 : credentials.hashCode());
		result = prime * result + ((principal == null) ? 0 : principal.hashCode());
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
		if (principal == null) {
			if (other.principal != null)
				return false;
		} else if (!principal.equals(other.principal)) {
			return false;
		}
		return true;
	}

}
