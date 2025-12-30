package org.entur.jwt.junit5;

import org.entur.jwt.junit5.configuration.resolve.ResourceServerConfiguration;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.api.extension.ParameterContext;

import java.lang.annotation.Annotation;

public interface AccessTokenEncoder {

    String encode(ParameterContext parameterContext, ExtensionContext extensionContext, Annotation authorizationServer, AuthorizationServerEncoder encoder, ResourceServerConfiguration configuration);

}
