package org.entur.jwt.junit5.entur.test.auth0;

import java.lang.annotation.Annotation;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;

import org.entur.jwt.junit5.impl.DefaultAuthorizationServerEncoder;

public class PartnerAuth0AuthorizationServerEncoder extends DefaultAuthorizationServerEncoder {

	@Override
	public String getToken(Annotation annotation, Map<String, Object> claims, Map<String, Object> headers) {
		
		if(annotation instanceof PartnerAuth0AuthorizationServer) {
			PartnerAuth0AuthorizationServer server = (PartnerAuth0AuthorizationServer)annotation;
			
			Map<String, Object> namespacedClaims = new HashMap<>();
			
			for (Entry<String, Object> entry : claims.entrySet()) {
				if(isStandardClaim(entry.getKey())) {
					namespacedClaims.put(entry.getKey(), entry.getValue());
				} else {
					namespacedClaims.put(server.namespace() + entry.getKey(), entry.getValue());
				}
			}
			return super.getToken(annotation, namespacedClaims, headers);
		}
		
		return super.getToken(annotation, claims, headers);
	}
	
	@Override
	public boolean isStandardClaim(String name) {
		return super.isStandardClaim(name) || name.equals("permissions");
	}
	
}
