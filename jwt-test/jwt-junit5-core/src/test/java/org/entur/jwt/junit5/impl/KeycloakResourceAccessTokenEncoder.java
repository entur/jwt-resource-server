package org.entur.jwt.junit5.impl;

import java.util.Map;
import java.util.Optional;

import org.entur.jwt.junit5.configuration.resolve.ResourceServerConfiguration;
import org.entur.jwt.junit5.impl.DefaultAccessTokenEncoder;
import org.junit.jupiter.api.extension.ParameterContext;

public class KeycloakResourceAccessTokenEncoder extends DefaultAccessTokenEncoder {

	public Map<String, Object> encodeClaims(ParameterContext parameterContext, ResourceServerConfiguration resolver) {
		Map<String, Object> encode = super.encodeClaims(parameterContext, resolver);

		Optional<KeycloakResourceAccessToken> a = parameterContext.findAnnotation(KeycloakResourceAccessToken.class);
		if(a.isPresent()) {
			encode(encode, a.get());			
		}

		return encode;
	}

	private void encode(Map<String, Object> encode, KeycloakResourceAccessToken partnerAccessToken) {
		encode.put("https://www.mock.com/organisationID", partnerAccessToken.myId());
	}
}
