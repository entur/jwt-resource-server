package org.entur.jwt.verifier.config;

import java.util.ArrayList;
import java.util.List;

public class JwtClaimsProperties {

    protected List<String> audiences = new ArrayList<>();

    /** note: property is expires-at-leeway */
    protected long expiresAtLeeway;
    /** note: property is issued-at-leeway */
    protected long issuedAtLeeway;

    private List<JwtClaimConstraintProperties> require = new ArrayList<>();

    public List<JwtClaimConstraintProperties> getRequire() {
        return require;
    }

    public void setRequire(List<JwtClaimConstraintProperties> required) {
        this.require = required;
    }

    public List<String> getAudiences() {
        return audiences;
    }

    public void setAudiences(List<String> audiences) {
        this.audiences = audiences;
    }

    public long getExpiresAtLeeway() {
        return expiresAtLeeway;
    }

    public void setExpiresAtLeeway(long expiresAtLeeway) {
        this.expiresAtLeeway = expiresAtLeeway;
    }

    public long getIssuedAtLeeway() {
        return issuedAtLeeway;
    }

    public void setIssuedAtLeeway(long issuedAtLeeway) {
        this.issuedAtLeeway = issuedAtLeeway;
    }

}
