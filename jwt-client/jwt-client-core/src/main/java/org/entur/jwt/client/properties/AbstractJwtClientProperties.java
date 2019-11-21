package org.entur.jwt.client.properties;

public abstract class AbstractJwtClientProperties {

	protected boolean enabled;
	
    protected String clientId;
    protected String secret;
    protected String audience;
    protected String scope;

    protected String protocol = null;
	protected int port = -1;
	protected String host;
	
	protected Integer connectTimeout;
	protected Integer readTimeout;

	protected boolean retrying = true;
	
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

	public Integer getConnectTimeout() {
		return connectTimeout;
	}

	public void setConnectTimeout(Integer connectTimeout) {
		this.connectTimeout = connectTimeout;
	}

	public Integer getReadTimeout() {
		return readTimeout;
	}

	public void setReadTimeout(Integer readTimeout) {
		this.readTimeout = readTimeout;
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
}