package org.entur.jwt.junit5.impl;

import org.entur.jwt.junit5.AuthorizationServer;
import org.entur.jwt.junit5.AuthorizationServerEncoder;

import java.io.IOException;
import java.lang.annotation.Annotation;
import java.nio.file.Path;
import java.nio.file.Paths;

public class AuthorizationServerImplementation {

    private AuthorizationServer authorizationServer;
    private Annotation annotation;
    private AuthorizationServerEncoder authorizationServerEncoder;
    private Path jsonWebKeysPath;

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
            throw new IllegalArgumentException("Unable to initialize encoder type " + encoder.getName(), e);
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

    /**
     * Get a file containing the JSON Web Keys. The file is written once, atomically, so that it
     * can be read while (other) tests are running.
     *
     * @return path to JSON Web Keys file
     * @throws IOException if the file could not be written
     */

    public synchronized Path getJsonWebKeysPath() throws IOException {
        if (jsonWebKeysPath == null) {
            String jsonWebKeys = getJsonWebKeys();

            // delete on exit, do not delete after use.
            // for certain frameworks (i.e. spring), context is reused and this
            // file might come in handy later
            Path path = Paths.get(System.getProperty("java.io.tmpdir"), jsonWebKeys.hashCode() + ".jwk.json");
            path.toFile().deleteOnExit(); // https://stackoverflow.com/questions/28752006/alternative-to-file-deleteonexit-in-java-nio

            AtomicFiles.write(path, jsonWebKeys);

            jsonWebKeysPath = path;
        }
        return jsonWebKeysPath;
    }

    public synchronized void setEncoder(AuthorizationServerEncoder encoder) {
        this.authorizationServerEncoder = encoder;
        this.jsonWebKeysPath = null;
    }

    public String getId() {
        return authorizationServer.value();
    }

    public boolean matches(AuthorizationServer server, Annotation source) {
        return server.equals(this.authorizationServer) && source.equals(this.annotation);
    }
}
