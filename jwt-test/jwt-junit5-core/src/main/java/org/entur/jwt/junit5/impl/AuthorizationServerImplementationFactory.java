package org.entur.jwt.junit5.impl;

import java.lang.annotation.Annotation;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import org.entur.jwt.junit5.AuthorizationServer;

public class AuthorizationServerImplementationFactory {

	public List<AuthorizationServerImplementation> create(Class<?> testClass) {
		List<AuthorizationServerImplementation> results = new ArrayList<>();
		Annotation[] annotations = testClass.getAnnotations();
		
		for(Annotation annotation : annotations) {
			createFromAnnotation(annotation, results);
		}
		return results;
	}

	private void createFromAnnotation(Annotation annotation, List<AuthorizationServerImplementation> results) {
		if(annotation instanceof AuthorizationServer) {
			AuthorizationServer authorizationServer = (AuthorizationServer)annotation;

			results.add(new AuthorizationServerImplementation(authorizationServer, annotation));
		} else if(annotation instanceof AuthorizationServer.List) {
			AuthorizationServer.List l = (AuthorizationServer.List)annotation;
			for(AuthorizationServer authorizationServer : l.value()) {
				results.add(new AuthorizationServerImplementation(authorizationServer, annotation));
			}
		} else {
			createFromMetaAnnotation(annotation, results);
		}
	}

	private void createFromMetaAnnotation(Annotation annotation, List<AuthorizationServerImplementation> results) {
		// https://dzone.com/articles/what-are-meta-annotations-in-java
		// copy approach from junit AnnotationUtils
		Optional<AuthorizationServer> single = AnnotationUtils.findAnnotation(annotation.getClass(), AuthorizationServer.class);
		if(single.isPresent()) {
			AuthorizationServer authorizationServer = single.get();

			results.add(new AuthorizationServerImplementation(authorizationServer, annotation));
		}
		Optional<AuthorizationServer.List> list = AnnotationUtils.findAnnotation(annotation.getClass(), AuthorizationServer.List.class);
		if(list.isPresent()) {
			for(AuthorizationServer authorizationServer : list.get().value()) {
				results.add(new AuthorizationServerImplementation(authorizationServer, annotation));
			}
		}
	}

}
