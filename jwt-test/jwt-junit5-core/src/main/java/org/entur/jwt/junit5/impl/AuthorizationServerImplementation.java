package org.entur.jwt.junit5.impl;

import java.lang.annotation.Annotation;

import org.entur.jwt.junit5.AuthorizationServer;
import org.entur.jwt.junit5.AuthorizationServerEncoder;

public class AuthorizationServerImplementation {

	private AuthorizationServer authorizationServer;
	private Annotation annotation;
	private AuthorizationServerEncoder encoder;
	
	public AuthorizationServerImplementation(AuthorizationServer server, Annotation source) {
		this.authorizationServer = server;
		this.annotation = source;
		this.encoder = getAuthorizationServerEncoder(server);
	}
	
	protected AuthorizationServerEncoder getAuthorizationServerEncoder(AuthorizationServer token) {
    	Class<?> encoder = (Class<?>) token.encoder();
    	try {
			return (AuthorizationServerEncoder) encoder.newInstance();
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}
	
	public AuthorizationServerEncoder getEncoder() {
		return encoder;
	}

	public AccessTokenImplementationFactory createAccessTokenFactory() {
		return new AccessTokenImplementationFactory(this);
	}
	
	public Annotation getAnnotation() {
		return annotation;
	}
	
	public AuthorizationServer getAuthorizationServer() {
		return authorizationServer;
	}
	
	public String getJsonWebKeys() {
		return encoder.getJsonWebKeys(annotation);
	}
	
	public void setEncoder(AuthorizationServerEncoder encoder) {
		this.encoder = encoder;
	}
	
	public String getId() {
		return authorizationServer.value();
	}
}
