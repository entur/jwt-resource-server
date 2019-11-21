package org.entur.jwt.junit5;

import java.lang.annotation.Annotation;
import java.util.Map;

public interface AuthorizationServerEncoder {
	
	String getJsonWebKeys(Annotation authorizationServer);

	String getToken(Annotation authorizationServer, Map<String, Object> claims, Map<String, Object> headers);
}
