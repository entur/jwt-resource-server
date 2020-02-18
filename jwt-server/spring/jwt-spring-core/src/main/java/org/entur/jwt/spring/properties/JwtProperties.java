package org.entur.jwt.spring.properties;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.entur.jwt.verifier.config.JwtClaimsProperties;
import org.entur.jwt.verifier.config.JwkProperties;
import org.entur.jwt.verifier.config.JwtTenantProperties;

public class JwtProperties {

    private boolean enabled = true;

    private MdcProperties mdc = new MdcProperties();

    private Map<String, JwtTenantProperties> tenants = new HashMap<>();

    /**
     * Tenant filter (on tenant name). This is a useful feature when configuration
     * is shared across multiple applications, i.e. like a common config-map in
     * Kubernetes.
     */
    private List<String> filter = null; //

    private JwkProperties jwk = new JwkProperties();

    private JwtClaimsProperties claims = new JwtClaimsProperties();

    public Map<String, JwtTenantProperties> getTenants() {
        return tenants;
    }

    public void setTenants(Map<String, JwtTenantProperties> tenants) {
        this.tenants = tenants;
    }

    public JwkProperties getJwk() {
        return jwk;
    }

    public void setJwk(JwkProperties jwk) {
        this.jwk = jwk;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public MdcProperties getMdc() {
        return mdc;
    }

    public void setMdc(MdcProperties mdc) {
        this.mdc = mdc;
    }

    public List<String> getFilter() {
        return filter;
    }

    public void setFilter(List<String> filter) {
        this.filter = filter;
    }

    public JwtClaimsProperties getClaims() {
        return claims;
    }

    public void setClaims(JwtClaimsProperties claims) {
        this.claims = claims;
    }

}
