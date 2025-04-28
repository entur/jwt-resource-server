package org.entur.jwt.junit5.impl;

import java.lang.annotation.Annotation;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import org.entur.jwt.junit5.AuthorizationServer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class AuthorizationServerImplementationFactory {

    private static Logger LOGGER = LoggerFactory.getLogger(AuthorizationServerImplementationFactory.class);

    private List<AuthorizationServerImplementation> servers = new ArrayList<>();

    public AuthorizationServerImplementationFactory() {
    }

    public List<AuthorizationServerImplementation> create(Class<?> testClass) {
        List<AuthorizationServerImplementation> results = new ArrayList<>();
        Annotation[] annotations = testClass.getAnnotations();

        for (Annotation annotation : annotations) {
            createFromAnnotation(annotation, results);
        }
        return results;
    }

    private void createFromAnnotation(Annotation annotation, List<AuthorizationServerImplementation> results) {
        if (annotation instanceof AuthorizationServer) {
            AuthorizationServer authorizationServer = (AuthorizationServer) annotation;

            results.add(add(annotation, authorizationServer));
        } else if (annotation instanceof AuthorizationServer.List) {
            AuthorizationServer.List l = (AuthorizationServer.List) annotation;
            for (AuthorizationServer authorizationServer : l.value()) {
                results.add(add(annotation, authorizationServer));
            }
        } else {
            createFromMetaAnnotation(annotation, results);
        }
    }

    public synchronized AuthorizationServerImplementation add(Annotation annotation, AuthorizationServer authorizationServer) {
        for (AuthorizationServerImplementation f : servers) {
            if(f.matches(authorizationServer, annotation)) {
                if(LOGGER.isTraceEnabled()) LOGGER.trace("Found existing authorization server " + f.getId() + " " + f.getJsonWebKeys().hashCode());
                return f;
            }
        }
        AuthorizationServerImplementation authorizationServerImplementation = new AuthorizationServerImplementation(authorizationServer, annotation);
        if(LOGGER.isTraceEnabled()) LOGGER.trace("Create new authorization server " + authorizationServer.value() + " " + authorizationServerImplementation.getJsonWebKeys().hashCode());
        servers.add(authorizationServerImplementation);
        return authorizationServerImplementation;
    }

    private void createFromMetaAnnotation(Annotation annotation, List<AuthorizationServerImplementation> results) {
        // https://dzone.com/articles/what-are-meta-annotations-in-java
        // copy approach from junit AnnotationUtils
        Optional<AuthorizationServer> single = AnnotationUtils.findAnnotation(annotation.getClass(), AuthorizationServer.class);
        if (single.isPresent()) {
            AuthorizationServer authorizationServer = single.get();

            results.add(add(annotation, authorizationServer));
        }
        Optional<AuthorizationServer.List> list = AnnotationUtils.findAnnotation(annotation.getClass(), AuthorizationServer.List.class);
        if (list.isPresent()) {
            for (AuthorizationServer authorizationServer : list.get().value()) {
                results.add(add(annotation, authorizationServer));
            }
        }
    }

    public List<AuthorizationServerImplementation> getServers() {
        return servers;
    }
}
