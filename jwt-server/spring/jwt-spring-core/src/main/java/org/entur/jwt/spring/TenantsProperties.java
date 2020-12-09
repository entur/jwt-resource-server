package org.entur.jwt.spring;

import java.util.HashMap;
import java.util.Map;

/**
 * 
 * Support for per-tenant additional custom properties / context data
 * 
 */

public class TenantsProperties {

	private Map<String, TenantProperties> issuers = new HashMap<>();
	private Map<String, TenantProperties> names = new HashMap<>();
	
	public void add(TenantProperties properties) {
		names.put(properties.getName(), properties);
		issuers.put(properties.getIssuer(), properties);
	}
	
	public TenantProperties getByIssuer(String issuer) {
		return issuers.get(issuer);
	}
	public TenantProperties getByName(String issuer) {
		return issuers.get(issuer);
	}
}
