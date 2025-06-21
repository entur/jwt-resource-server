package org.entur.jwt.junit5.configuration.resolve;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Properties;

import org.entur.jwt.junit5.extention.AuthorizationServerExtension;
import org.junit.jupiter.api.extension.ExtensionContext;

public class PropertiesFileAuthorizationServerConfigurationResolver implements ResourceServerConfigurationResolver {

    private Path path;
    private String prefix;

    public PropertiesFileAuthorizationServerConfigurationResolver() throws IOException {
        this(AuthorizationServerExtension.detectParentPath(), "entur.jwt.tenants");
    }

    public PropertiesFileAuthorizationServerConfigurationResolver(Path path, String prefix) {
        this.path = path;
        this.prefix = prefix;
    }

    @Override
    public ResourceServerConfiguration resolve(ExtensionContext context) throws Exception {
        Properties properties = new Properties();
        try (InputStream in = Files.newInputStream(path)) {
            properties.load(in);
        }

        return new PropertiesAuthorizationServerConfiguration(prefix, properties);
    }

}
