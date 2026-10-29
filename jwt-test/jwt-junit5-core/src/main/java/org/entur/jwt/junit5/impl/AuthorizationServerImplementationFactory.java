package org.entur.jwt.junit5.impl;

import org.entur.jwt.junit5.AuthorizationServer;

import java.io.IOException;
import java.lang.annotation.Annotation;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

public class AuthorizationServerImplementationFactory {

    public static final String ON_THE_FLY_PROPERTY = ".on-the-fly";

    private List<AuthorizationServerImplementation> servers = new ArrayList<>();

    public AuthorizationServerImplementationFactory() {
    }

    public List<AuthorizationServerImplementation> create(Class<?> testClass) {
        List<AuthorizationServerImplementation> results = new ArrayList<>();
        Annotation[] annotations = testClass.getAnnotations();

        for (Annotation annotation : annotations) {
            createFromAnnotation(annotation, results);
        }

        // check for @Nested unit tests
        Class<?> enclosingClass = testClass.getEnclosingClass();
        while(enclosingClass != null) {
            Annotation[] enclosingClassAnnotations = enclosingClass.getAnnotations();
            for (Annotation annotation : enclosingClassAnnotations) {
                createFromAnnotation(annotation, results);
            }
            enclosingClass = enclosingClass.getEnclosingClass();
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
                return f;
            }
        }
        AuthorizationServerImplementation authorizationServerImplementation = new AuthorizationServerImplementation(authorizationServer, annotation);
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


    public static Map<String, Object> getProperties(String prefix, List<AuthorizationServerImplementation> implementations) throws IOException {
        Map<String, Object> properties = new HashMap<>();
        for (int i = 0; i < implementations.size(); i++) {
            AuthorizationServerImplementation implementation = implementations.get(i);

            AuthorizationServer authorizationServer = implementation.getAuthorizationServer();

            // write certificates to temp file (once); get as an URI.
            // TODO do this right before the test method is called, so that
            // additional configuration parameters can be included
            Path path = implementation.getJsonWebKeysPath();

            String key = authorizationServer.value();
            if (key.isEmpty()) {
                if (implementations.size() > 1) {
                    throw new IllegalArgumentException("Specify authorization server id in multi-tenant tests.");
                }
                key = "mock";
                properties.put(prefix + "." + key + ON_THE_FLY_PROPERTY, "true");
            }
            properties.put(prefix + "." + key + ".jwk.location", path.toUri().toString());
        }
        return properties;
    }

}
