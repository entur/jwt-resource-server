package org.entur.jwt.junit5.impl;

import org.entur.jwt.junit5.AuthorizationServer;
import org.junit.jupiter.api.Nested;
import org.junit.platform.commons.support.AnnotationSupport;

import java.io.File;
import java.io.IOException;
import java.lang.annotation.Annotation;
import java.lang.reflect.Modifier;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

public class AuthorizationServerImplementationFactory {

    public static final String ON_THE_FLY_PROPERTY = ".on-the-fly";

    // tenant id in the properties for an authorization server without id
    public static final String ON_THE_FLY_TENANT = "mock";

    private List<AuthorizationServerImplementation> servers = new ArrayList<>();

    public AuthorizationServerImplementationFactory() {
    }

    public List<AuthorizationServerImplementation> create(Class<?> testClass) {
        List<AuthorizationServerImplementation> results = new ArrayList<>();

        createFromClass(testClass, results);

        // check for @Nested unit tests
        // note: like for JUnit and Spring, static nested classes do not inherit the configuration of the enclosing class
        Class<?> nestedClass = testClass;
        while(isNested(nestedClass)) {
            Class<?> enclosingClass = nestedClass.getEnclosingClass();
            createFromClass(enclosingClass, results);
            nestedClass = enclosingClass;
        }

        return results;
    }

    private void createFromClass(Class<?> testClass, List<AuthorizationServerImplementation> results) {
        List<AuthorizationServerImplementation> implementations = new ArrayList<>();
        for (Annotation annotation : testClass.getAnnotations()) {
            createFromAnnotation(annotation, implementations);
        }

        // an authorization server of an inner (@Nested) class overrides the one of an enclosing class with the same id,
        // so that tokens are signed by the same authorization server which publishes its keys
        Set<String> overridden = new HashSet<>();
        for (AuthorizationServerImplementation result : results) {
            overridden.add(result.getId());
        }

        for (AuthorizationServerImplementation implementation : implementations) {
            String id = implementation.getId();
            if (overridden.contains(id)) {
                continue;
            }
            AuthorizationServerImplementation existing = getById(results, id);
            if (existing == null) {
                results.add(implementation);
            } else if (existing != implementation) {
                throw new IllegalArgumentException("Multiple authorization servers with id '" + id + "' on " + testClass.getName() + ", please specify a unique id for each authorization server");
            }
        }
    }

    private static AuthorizationServerImplementation getById(List<AuthorizationServerImplementation> implementations, String id) {
        for (AuthorizationServerImplementation implementation : implementations) {
            if (implementation.getId().equals(id)) {
                return implementation;
            }
        }
        return null;
    }

    /**
     * @param testClass a test class
     * @return the test class itself, or the outermost enclosing class of a {@literal @}Nested test class
     */

    public static Class<?> getTopLevelTestClass(Class<?> testClass) {
        Class<?> topLevelTestClass = testClass;
        while (isNested(topLevelTestClass)) {
            topLevelTestClass = topLevelTestClass.getEnclosingClass();
        }
        return topLevelTestClass;
    }

    private static boolean isNested(Class<?> testClass) {
        // i.e. an inner (non-static) class annotated with @Nested, like JUnit
        return testClass.isMemberClass() && !Modifier.isStatic(testClass.getModifiers()) && AnnotationSupport.isAnnotated(testClass, Nested.class);
    }

    private void createFromAnnotation(Annotation annotation, List<AuthorizationServerImplementation> results) {
        if (annotation instanceof AuthorizationServer) {
            AuthorizationServer authorizationServer = (AuthorizationServer) annotation;

            results.add(add(annotation, authorizationServer));
        } else if (annotation instanceof AuthorizationServer.List) {
            AuthorizationServer.List l = (AuthorizationServer.List) annotation;
            for (AuthorizationServer authorizationServer : l.value()) {
                // like a directly declared authorization server (i.e. one inherited within a container, one declared directly)
                results.add(add(authorizationServer, authorizationServer));
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
        // note: the source is the annotation which carries the meta-annotation (i.e. not necessarily the annotation on the test class),
        // so that its attributes are available to the encoder also when used within a composed annotation
        // a composed annotation might carry several authorization servers
        for (Annotation source : AnnotationUtils.findMetaAnnotatedAnnotations(annotation, AuthorizationServer.class)) {
            AuthorizationServer authorizationServer = source.annotationType().getDeclaredAnnotation(AuthorizationServer.class);

            results.add(add(source, authorizationServer));
        }
        for (Annotation source : AnnotationUtils.findMetaAnnotatedAnnotations(annotation, AuthorizationServer.List.class)) {
            for (AuthorizationServer authorizationServer : source.annotationType().getDeclaredAnnotation(AuthorizationServer.List.class).value()) {
                results.add(add(source, authorizationServer));
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
            // test classes running in parallel might write (and read) the same file
            writeAtomically(path, jsonWebKeys);
            String key = authorizationServer.value();
            if (key.isEmpty()) {
                if (implementations.size() > 1) {
                    throw new IllegalArgumentException("Specify authorization server id in multi-tenant tests.");
                }
                key = ON_THE_FLY_TENANT;
                properties.put(prefix + "." + key + ON_THE_FLY_PROPERTY, "true");
            }
            properties.put(prefix + "." + key + ".jwk.location", path.toUri().toString());
        }
        return properties;
    }

    /**
     * Write a file so that concurrent readers never see a partially written file, i.e. when test classes
     * run in parallel.
     *
     * @param path file to write
     * @param content file content
     * @throws IOException if the file could not be written
     */

    public static void writeAtomically(Path path, String content) throws IOException {
        writeAtomically(path, content.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Write a file so that concurrent readers never see a partially written file.
     *
     * @param path file to write
     * @param content file content
     * @throws IOException if the file could not be written
     */

    public static void writeAtomically(Path path, byte[] content) throws IOException {
        Path absolutePath = path.toAbsolutePath();
        Path temp = Files.createTempFile(absolutePath.getParent(), absolutePath.getFileName().toString(), ".tmp");
        try {
            Files.write(temp, content);
            try {
                Files.move(temp, absolutePath, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            } catch (AtomicMoveNotSupportedException e) {
                Files.move(temp, absolutePath, StandardCopyOption.REPLACE_EXISTING);
            }
        } finally {
            Files.deleteIfExists(temp);
        }
    }
}
