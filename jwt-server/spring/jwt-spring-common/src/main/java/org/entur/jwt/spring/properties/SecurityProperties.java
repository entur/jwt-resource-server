package org.entur.jwt.spring.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "entur")
public class SecurityProperties {

    private AuthorizationProperties authorization = new AuthorizationProperties();

    private CorsProperties cors = new CorsProperties();

    private JwtProperties jwt = new JwtProperties();

    public CorsProperties getCors() {
        return cors;
    }

    public void setCors(CorsProperties cors) {
        this.cors = cors;
    }

    public void setJwt(JwtProperties oidc) {
        this.jwt = oidc;
    }

    public JwtProperties getJwt() {
        return jwt;
    }

    public AuthorizationProperties getAuthorization() {
        return authorization;
    }
    
    public void setAuthorization(AuthorizationProperties authorization) {
        this.authorization = authorization;
    }
}
