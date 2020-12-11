package org.entur.jwt.junit5.configuration.enrich;

import java.io.BufferedWriter;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Properties;

import org.entur.jwt.junit5.AuthorizationServer;
import org.entur.jwt.junit5.impl.AuthorizationServerImplementation;

public abstract class AbstractPropertiesResourceServerConfigurationEnricher implements ResourceServerConfigurationEnricher {

    public static final String ON_THE_FLY_PROPERTY = ".on-the-fly";
    
    protected String prefix;

    public AbstractPropertiesResourceServerConfigurationEnricher() throws IOException {
        this("entur.jwt.tenants");
    }

    public AbstractPropertiesResourceServerConfigurationEnricher(String prefix) {
        this.prefix = prefix;
    }

    public void setPrefix(String prefix) {
        this.prefix = prefix;
    }

    protected Properties getProperties(List<AuthorizationServerImplementation> implementations) throws IOException {
        Properties properties = new Properties();
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
