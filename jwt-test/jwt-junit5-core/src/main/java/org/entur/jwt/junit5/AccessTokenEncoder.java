package org.entur.jwt.junit5;

import java.lang.annotation.Annotation;

import org.entur.jwt.junit5.configuration.resolve.ResourceServerConfiguration;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.api.extension.ParameterContext;

public interface AccessTokenEncoder {

	<S extends Annotation> String encode(ParameterContext parameterContext, ExtensionContext extensionContext, Annotation authorizationServer, AuthorizationServerEncoder encoder, ResourceServerConfiguration configuration);
	
}
