package org.entur.jwt.junit5.impl;

import java.io.BufferedWriter;
import java.io.File;
import java.io.IOException;
import java.lang.annotation.Annotation;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;

import org.entur.jwt.junit5.AuthorizationServer;

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

            // write certificates to temp file; get as an URI.
            // TODO do this right before the test method is called, so that
            // additional configuration parameters can be included

            // also, delete on exit, do not delete after use.
            // for certain frameworks (i.e. spring), context is reused and this
            // file might come in handy later

            String tempDir = System.getProperty("java.io.tmpdir");

            String jsonWebKeys = implementation.getJsonWebKeys();

            File tempFile = new File(tempDir, jsonWebKeys.hashCode() + ".jwk.json");
            tempFile.deleteOnExit(); // https://stackoverflow.com/questions/28752006/alternative-to-file-deleteonexit-in-java-nio
            Path path = tempFile.toPath();
            try (BufferedWriter writer = Files.newBufferedWriter(tempFile.toPath(), StandardCharsets.UTF_8)) {
                writer.write(implementation.getJsonWebKeys());
            }
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
