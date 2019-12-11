package org.entur.jwt.junit5.configuration.enrich;

import java.io.BufferedWriter;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.Properties;

import org.entur.jwt.junit5.configuration.resolve.ResourceServerConfiguration;
import org.entur.jwt.junit5.impl.AuthorizationServerImplementation;
import org.junit.jupiter.api.extension.ExtensionContext;

public class PropertiesFileResourceServerConfigurationEnricher extends AbstractPropertiesResourceServerConfigurationEnricher {

    protected Path output;

    public PropertiesFileResourceServerConfigurationEnricher() throws IOException {
        this("entur.jwt.tenants", Paths.get("jwt.junit5.properties"));
    }

    public PropertiesFileResourceServerConfigurationEnricher(String prefix, Path output) {
        super(prefix);
        this.output = output;
    }

    public void setOutput(Path output) {
        this.output = output;
    }

    @Override
    public void beforeAll(List<AuthorizationServerImplementation> authorizationServers, ExtensionContext context) throws IOException {
        Properties properties = getProperties(authorizationServers);

        try (BufferedWriter writer = Files.newBufferedWriter(output, StandardCharsets.UTF_8)) {
            properties.store(writer, null);
        }
    }

    @Override
    public void beforeEach(ResourceServerConfiguration configuration, ExtensionContext context) {
        // do nothing
    }

    @Override
    public void afterAll(ExtensionContext context) throws IOException {
        if (output != null) {
            File file = output.toFile(); // using file because sonarqube says it has better performance
            if (file.exists()) {
                if (!file.delete()) {
                    throw new IOException("Unable to delete " + output);
                }
            }
        }
    }

}
