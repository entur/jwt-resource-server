package org.entur.jwt.client.properties;

public abstract class AbstractJwtClientProperties {

    protected boolean enabled = true;

    protected String clientId;
    protected String secret;
    protected String audience;
    protected String scope;

    protected String protocol = "https";
    protected int port = -1;
    protected String host;

    protected boolean retrying = true;

    protected boolean health = true;

    protected JwtClientCache cache = new JwtClientCache();

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public String getSecret() {
        return secret;
    }

    public void setSecret(String secret) {
        this.secret = secret;
    }

    public String getAudience() {
        return audience;
    }

    public void setAudience(String audience) {
        this.audience = audience;
    }

    public String getProtocol() {
        return protocol;
    }

    public void setProtocol(String protocol) {
        this.protocol = protocol;
    }

    public int getPort() {
        return port;
    }

    public void setPort(int port) {
        this.port = port;
    }

    public String getHost() {
        return host;
    }

    public void setHost(String host) {
        this.host = host;
    }

    public JwtClientCache getCache() {
        return cache;
    }

    public void setCache(JwtClientCache cache) {
        this.cache = cache;
    }

    public String getScope() {
        return scope;
    }

    public void setScope(String scope) {
        this.scope = scope;
    }

    public void setRetrying(boolean retrying) {
        this.retrying = retrying;
    }

    public boolean isRetrying() {
        return retrying;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public boolean isEnabled() {
        return enabled;
    }
    
    public boolean isHealth() {
        return health;
    }
    
    public void setHealth(boolean health) {
        this.health = health;
    }
}