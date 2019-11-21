package org.entur.jwt.client;

import java.nio.charset.StandardCharsets;

/**
 * Client Credentials builder scaffold
 * 
 * @see <a href="https://www.sitepoint.com/self-types-with-javas-generics/">https://www.sitepoint.com/self-types-with-javas-generics/</a> 
 */


public abstract class AbstractClientCredentialsBuilder<B extends AbstractClientCredentialsBuilder<B>> {

    protected static final String KEY_AUDIENCE = "audience";
    protected static final String KEY_SCOPE = "scope";
    protected static final String HEADER_AUTHORIZATION = "authorization";

	protected static final String KEY_CLIENT_CREDENTIALS = "client_credentials";
    protected static final String KEY_GRANT_TYPE = "grant_type";

    protected static final String KEY_CLIENT_ID = "client_id";
    protected static final String KEY_SECRET = "client_secret";
    
    protected static String createHeader(String clientId, String secret) {
    	// see https://www.base64encoder.io/java/ and 
        StringBuffer buf = new StringBuffer(clientId);
        buf.append(':').append(secret);
        
        // encode with padding
        return "Basic " + java.util.Base64.getUrlEncoder().encodeToString(buf.toString().getBytes(StandardCharsets.UTF_8));
    }    
    
    protected String protocol = "https";
	protected int port = -1;
	protected String host;
	protected String issuePath;
	protected String refreshPath;
	protected String revokePath;

	protected String clientId;
	protected String secret;

	protected String audience;
	protected String scope;

	public B withHost(String host) {
		this.host = host;
        return (B) this;
	}
	
	public B withProtocol(String protocol) {
		this.protocol = protocol;
        return (B) this;
	}

	public B withIssuePath(String issuePath) {
		this.issuePath = issuePath;
        return (B) this;
	}

	public B withRefreshPath(String refreshPath) {
		this.refreshPath = refreshPath;
        return (B) this;
	}

	public B withRevokePath(String revokePath) {
		this.revokePath = revokePath;
        return (B) this;
	}

	public B withClientId(String clientId) {
		this.clientId = clientId;
        return (B) this;
	}

	public B withSecret(String secret) {
		this.secret = secret;
        return (B) this;
	}

	public B withAudience(String audience) {
		this.audience = audience;
        return (B) this;
	}

	public B withScope(String scope) {
		this.scope = scope;
        return (B) this;
	}
	
	public abstract ClientCredentials build();
	
	protected ClientCredentials build(boolean authorizationHeader) {
		
		if(clientId == null) {
			throw new IllegalStateException("Expected client-id");
		}
		if(host == null) {
			throw new IllegalStateException("Expected host");
		}
		if(issuePath == null) {
			throw new IllegalStateException("Expected issue (token) path");
		}
		if(secret == null) {
			throw new IllegalStateException("Expected secret");
		}
		
		DefaultClientCredentials credentials = newClientCredentials();
		
		credentials.setProtocol(protocol);
		credentials.setPort(port);
		credentials.setHost(host);
		credentials.setIssuePath(issuePath);
		credentials.setRefreshPath(refreshPath);
		credentials.setRevokePath(revokePath);
		
		if(authorizationHeader) {
			credentials.addHeader("Authorization", createHeader(clientId, secret));
		} else {
			credentials.addParameter(KEY_CLIENT_ID, clientId);
			credentials.addParameter(KEY_SECRET, secret);
		}
		
		credentials.addParameter(KEY_GRANT_TYPE, KEY_CLIENT_CREDENTIALS);

		if(audience != null) {
			credentials.addParameter(KEY_AUDIENCE, audience);
		}
		if(scope != null) {
			credentials.addParameter(KEY_SCOPE, scope);
		}
		
		return credentials;
	}

	protected DefaultClientCredentials newClientCredentials() {
		return new DefaultClientCredentials();
	}

	

}
