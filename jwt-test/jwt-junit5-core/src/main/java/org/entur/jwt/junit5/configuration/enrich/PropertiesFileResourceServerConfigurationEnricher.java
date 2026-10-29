package org.entur.jwt.junit5.configuration.enrich;

import org.entur.jwt.junit5.configuration.resolve.ResourceServerConfiguration;
import org.entur.jwt.junit5.extention.AuthorizationServerExtension;
import org.entur.jwt.junit5.impl.AtomicFiles;
import org.entur.jwt.junit5.impl.AuthorizationServerImplementation;
import org.junit.jupiter.api.extension.ExtensionContext;

import java.io.IOException;
import java.io.StringWriter;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Properties;

/**
 * 
 * Write authorization server properties to a file, by default jwt.junit5.properties in the build directory.
 * <br>
 * The file is replaced atomically, but it is shared by all test classes; so test classes with different
 * authorization servers must not run concurrently.
 *
 */

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

        StringWriter writer = new StringWriter();
        p.store(writer, null);

        // replace the file atomically, so that it can be read while (other) tests are running
        AtomicFiles.write(output, writer.toString());
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
