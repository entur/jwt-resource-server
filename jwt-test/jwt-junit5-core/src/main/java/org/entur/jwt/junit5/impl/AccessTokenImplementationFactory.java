package org.entur.jwt.junit5.impl;

import org.entur.jwt.junit5.AccessToken;
import org.entur.jwt.junit5.AccessTokenEncoder;
import org.entur.jwt.junit5.configuration.resolve.ResourceServerConfiguration;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.api.extension.ParameterContext;

public class AccessTokenImplementationFactory {

    private AuthorizationServerImplementation server;

    public AccessTokenImplementationFactory(AuthorizationServerImplementation server) {
        super();
        this.server = server;
    }
    
    /**
     * Create authorization (i.e. access-token) string representation
     * 
     * @param token target token
     * @param parameterContext context
     * @param extensionContext extension
     * @param resolver configuration resolver
     * @return token as text
     */

    public String create(AccessToken token, ParameterContext parameterContext, ExtensionContext extensionContext, ResourceServerConfiguration resolver) {
        AccessTokenEncoder encoder = getAccessTokenEncoder(token);

        return encoder.encode(parameterContext, extensionContext, server.getAnnotation(), server.getEncoder(), resolver);
    }

    @SuppressWarnings("unchecked")
    protected <T extends AccessTokenEncoder> T getAccessTokenEncoder(AccessToken token) {
        Class<T> encoder = (Class<T>) token.encoder();
        try {
            return encoder.getDeclaredConstructor().newInstance();
        } catch (Exception e) {
            throw new IllegalArgumentException("Unable to initialize encoder type " + encoder.getClass().getName(), e);
        }
    }

}
