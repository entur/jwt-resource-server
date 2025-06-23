package org.entur.jwt.junit5.impl;

import java.lang.annotation.Annotation;

import org.entur.jwt.junit5.AuthorizationServer;
import org.entur.jwt.junit5.AuthorizationServerEncoder;

public class AuthorizationServerImplementation {

    private AuthorizationServer authorizationServer;
    private Annotation annotation;
    private AuthorizationServerEncoder authorizationServerEncoder;

    public AuthorizationServerImplementation(AuthorizationServer server, Annotation source) {
        this.authorizationServer = server;
        this.annotation = source;
        this.authorizationServerEncoder = getAuthorizationServerEncoder(server);
    }

    protected AuthorizationServerEncoder getAuthorizationServerEncoder(AuthorizationServer token) {
        Class<?> encoder = token.encoder();
        try {
            return (AuthorizationServerEncoder) encoder.getDeclaredConstructor().newInstance();
        } catch (Exception e) {
            throw new IllegalArgumentException("Unable to initialize encoder type " + encoder.getClass().getName(), e);
        }
    }

    public AuthorizationServerEncoder getEncoder() {
        return authorizationServerEncoder;
    }

    public Annotation getAnnotation() {
        return annotation;
    }

    public AuthorizationServer getAuthorizationServer() {
        return authorizationServer;
    }

    public String getJsonWebKeys() {
        return authorizationServerEncoder.getJsonWebKeys(annotation);
    }

    public void setEncoder(AuthorizationServerEncoder encoder) {
        this.authorizationServerEncoder = encoder;
    }

    public String getId() {
        return authorizationServer.value();
    }

    public boolean matches(AuthorizationServer server, Annotation source) {
        return server.equals(this.authorizationServer) && source.equals(this.annotation);
    }
}
