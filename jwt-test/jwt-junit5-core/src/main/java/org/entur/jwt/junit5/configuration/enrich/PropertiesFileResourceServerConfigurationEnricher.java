package org.entur.jwt.junit5.configuration.enrich;

import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import org.entur.jwt.junit5.configuration.resolve.ResourceServerConfiguration;
import org.entur.jwt.junit5.extention.AuthorizationServerExtension;
import org.entur.jwt.junit5.impl.AuthorizationServerImplementation;
import org.junit.jupiter.api.extension.ExtensionContext;

public class PropertiesFileResourceServerConfigurationEnricher extends AbstractPropertiesResourceServerConfigurationEnricher {

    protected Path output;

    public PropertiesFileResourceServerConfigurationEnricher() throws IOException {
        this("entur.jwt.tenants", AuthorizationServerExtension.detectParentPath());
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
        Map<String, Object> properties = getProperties(authorizationServers);
        Properties p = new Properties();

        for (Map.Entry<String, Object> e : properties.entrySet()) {
            p.put(e.getKey(), e.getValue());
        }

        try (BufferedWriter writer = Files.newBufferedWriter(output, StandardCharsets.UTF_8)) {
            p.store(writer, null);
        }
    }

    @Override
    public void beforeEach(ResourceServerConfiguration configuration, ExtensionContext context) {
        // do nothing
    }

    @Override
    public void afterAll(ExtensionContext context) throws IOException {
        // do nothing
    }

}
