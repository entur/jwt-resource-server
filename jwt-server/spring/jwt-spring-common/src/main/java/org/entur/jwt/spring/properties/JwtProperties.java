package org.entur.jwt.spring.properties;

import org.entur.jwt.spring.properties.jwk.JwkProperties;
import org.entur.jwt.spring.properties.jwk.JwtClaimsProperties;
import org.entur.jwt.spring.properties.jwk.JwtTenantProperties;

import java.util.HashMap;
import java.util.Map;

public class JwtProperties {

    private boolean enabled = true;

    private MdcProperties mdc = new MdcProperties();

    private Map<String, JwtTenantProperties> tenants = new HashMap<>();

    private JwkProperties jwk = new JwkProperties();

    private JwtClaimsProperties claims = new JwtClaimsProperties();

    public Map<String, JwtTenantProperties> getTenants() {
        return tenants;
    }

    private Flavours flavours = new Flavours();

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


    public JwtClaimsProperties getClaims() {
        return claims;
    }

    public void setClaims(JwtClaimsProperties claims) {
        this.claims = claims;
    }

    public Flavours getFlavours() {
        return flavours;
    }

    public void setFlavours(Flavours flavours) {
        this.flavours = flavours;
    }
}
