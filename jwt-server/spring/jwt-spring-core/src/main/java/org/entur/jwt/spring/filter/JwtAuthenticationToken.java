package org.entur.jwt.spring.filter;

import java.util.Collection;
import org.entur.jwt.verifier.JwtClaimException;
import org.entur.jwt.verifier.JwtClaimExtractor;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.SpringSecurityCoreVersion;


/**
 * Adapted copy of UsernamePasswordAuthentication.
 */

public class JwtAuthenticationToken<T> extends AbstractAuthenticationToken {

    private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;

	private final JwtClaimExtractor<T> extractor;
    private final T principal;
    private String credentials;
    
    public JwtAuthenticationToken(T principal, String credentials, Collection<? extends GrantedAuthority> authorities, JwtClaimExtractor<T> extractor) {
        super(authorities);
        this.principal = principal;
        this.credentials = credentials;
        this.extractor = extractor;
        super.setAuthenticated(true); // must use super, as we override
    }

	public String getCredentials() {
        return this.credentials;
    }

    public T getPrincipal() {
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
    
    public <V> V getClaim(String name, Class<V> type) throws JwtClaimException {
    	return extractor.getClaim(principal, name, type);
    }

}
