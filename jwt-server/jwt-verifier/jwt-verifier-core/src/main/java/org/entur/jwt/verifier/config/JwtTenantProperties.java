package org.entur.jwt.verifier.config;

public class JwtTenantProperties {

    private boolean enabled = true;

    protected String type;
    protected String issuer;

    protected JwkLocationProperties jwk;

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public JwkLocationProperties getJwk() {
        return jwk;
    }

    public void setJwk(JwkLocationProperties jwk) {
        this.jwk = jwk;
    }

    public String getIssuer() {
        return issuer;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }
    
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }
    
    public boolean isEnabled() {
        return enabled;
    }
}
