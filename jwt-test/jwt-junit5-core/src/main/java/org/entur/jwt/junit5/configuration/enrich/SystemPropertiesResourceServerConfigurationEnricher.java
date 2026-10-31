package org.entur.jwt.junit5.configuration.enrich;

import org.entur.jwt.junit5.configuration.resolve.ResourceServerConfiguration;
import org.entur.jwt.junit5.impl.AuthorizationServerImplementation;
import org.junit.jupiter.api.extension.ExtensionContext;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class SystemPropertiesResourceServerConfigurationEnricher extends AbstractPropertiesResourceServerConfigurationEnricher {

    // previous values, null if the property was not set
    private Map<String, String> previousValues;

    public SystemPropertiesResourceServerConfigurationEnricher() throws IOException {
        super();
    }

    @Override
    public void beforeAll(List<AuthorizationServerImplementation> authorizationServers, ExtensionContext context) throws IOException {
        Map<String, Object> properties = getProperties(authorizationServers);

        previousValues = new HashMap<>();
        for (Map.Entry<String, Object> entry : properties.entrySet()) {
            previousValues.put(entry.getKey(), System.getProperty(entry.getKey()));
            System.setProperty(entry.getKey(), entry.getValue().toString());
        }
    }

    @Override
    public void afterAll(ExtensionContext context) throws IOException {
        if (previousValues != null) {
            for (Map.Entry<String, String> entry : previousValues.entrySet()) {
                if (entry.getValue() == null) {
                    System.clearProperty(entry.getKey());
                } else {
                    System.setProperty(entry.getKey(), entry.getValue());
                }
            }
            previousValues = null;
        }
    }

    @Override
    public void beforeEach(ResourceServerConfiguration configuration, ExtensionContext context) {
        // do nothing
        // TODO generate keys here
    }

}
