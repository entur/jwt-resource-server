package org.entur.jwt.client;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;

public class DefaultClientCredentials implements ClientCredentials {

	protected String protocol = "https";
	protected int port = -1;
	protected String host;
	protected String issuePath;
	protected String refreshPath;
	protected String revokePath;

	protected Map<String, Object> parameters = new HashMap<>();
	protected Map<String, Object> headers = new HashMap<>();

	@Override
	public Map<String, Object> getHeaders() {
		return headers;
	}

	public URL getIssueURL() {
		return urlForPath(issuePath);
	}

	public URL getRevokeURL() {
		if(revokePath != null) {
			return urlForPath(revokePath);
		}
		return null;
	}

	@Override
	public URL getRefreshURL() {
		if(refreshPath != null) {
			return urlForPath(refreshPath);
		}
		return null;		
	}

	protected URL urlForPath(String path) {
		try {
			StringBuilder builder = new StringBuilder();
			
			builder.append(protocol);
			if(!protocol.contains("://")) {
				builder.append("://");
			}
			builder.append(host);
			if(port != -1) {
				builder.append(':');
				builder.append(port);
			}
			builder.append(path);
			return new URL(builder.toString());
		} catch(MalformedURLException e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	public Map<String, Object> getParameters() {
		return parameters;
	}

	public void addParameter(String key, Object value) {
		parameters.put(key, value);
	}
	public void addHeader(String key, Object value) {
		headers.put(key, value);
	}

	public String getHost() {
		return host;
	}
	public void setHost(String host) {
		this.host = host;
	}
	public String getIssuePath() {
		return issuePath;
	}
	public void setIssuePath(String issuePath) {
		this.issuePath = issuePath;
	}
	public String getRefreshPath() {
		return refreshPath;
	}
	public void setRefreshPath(String refreshPath) {
		this.refreshPath = refreshPath;
	}
	public String getRevokePath() {
		return revokePath;
	}
	public void setRevokePath(String revokePath) {
		this.revokePath = revokePath;
	}
	public void setParameters(Map<String, Object> parameters) {
		this.parameters = parameters;
	}

	public Object getParameter(String key) {
		return parameters.get(key);
	}

	public Object getHeader(String key) {
		return headers.get(key);
	}

	public void setHeaders(Map<String, Object> headers) {
		this.headers = headers;
	}
	
	public void setPort(int port) {
		this.port = port;
	}
	
	public int getPort() {
		return port;
	}
	
	public void setProtocol(String protocol) {
		this.protocol = protocol;
	}
	
	public String getProtocol() {
		return protocol;
	}

}
