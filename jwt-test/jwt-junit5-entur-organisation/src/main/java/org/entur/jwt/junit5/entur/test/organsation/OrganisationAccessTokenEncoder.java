package org.entur.jwt.junit5.entur.test.organsation;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import org.entur.jwt.junit5.configuration.resolve.ResourceServerConfiguration;
import org.entur.jwt.junit5.impl.DefaultAccessTokenEncoder;
import org.junit.jupiter.api.extension.ParameterContext;

public class OrganisationAccessTokenEncoder extends DefaultAccessTokenEncoder {

	private static final String ROLES = "roles";

	public Map<String, Object> encodeClaims(ParameterContext parameterContext, ResourceServerConfiguration resolver) {
		Map<String, Object> encode = super.encodeClaims(parameterContext, resolver);
		
		Optional<OrganisationToken> a = parameterContext.findAnnotation(OrganisationToken.class);
		if(a.isPresent()) {
			encode(encode, a.get());			
		}
		
		return encode;
	}

	private void encode(Map<String, Object> encode, OrganisationToken partnerAccessToken) {
    	/*
		  "resource_access": {
		    "xyz": {
		      "roles": [
		        "uma_protection"
		      ]
		    }
		  }
    	*/
		
		Map<String, Object> resourceAccess = new HashMap<>();
		encode.put("resource_access", resourceAccess);
		
		Map<String, Object> resource = new HashMap<>();
		resourceAccess.put(partnerAccessToken.resource(), resource);
		resource.put(ROLES, partnerAccessToken.resourceAccess());

		Map<String, Object> realmAccess = new HashMap<>();
		encode.put("realm_access", realmAccess);
		realmAccess.put(ROLES, partnerAccessToken.realmAccess());

		encode.put(ROLES, partnerAccessToken.roles());
	}
}
