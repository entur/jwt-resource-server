package org.entur.jwt.junit5.configuration.enrich;

import org.entur.jwt.junit5.impl.AuthorizationServerImplementation;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

public class SystemPropertiesResourceServerConfigurationEnricherTest {

    private static final String EXISTING = "entur.jwt.test.existing";
    private static final String MISSING = "entur.jwt.test.missing";

    @Test
    public void afterAllRestoresPreviousValues() throws IOException {
        System.setProperty(EXISTING, "original");
        System.clearProperty(MISSING);
        try {
            Map<String, Object> properties = new LinkedHashMap<>();
            properties.put(EXISTING, "overridden");
            properties.put(MISSING, "added");

            SystemPropertiesResourceServerConfigurationEnricher enricher = new SystemPropertiesResourceServerConfigurationEnricher() {
                @Override
                protected Map<String, Object> getProperties(List<AuthorizationServerImplementation> implementations) {
                    return properties;
                }
            };

            enricher.beforeAll(List.of(), null);
            assertEquals("overridden", System.getProperty(EXISTING));
            assertEquals("added", System.getProperty(MISSING));

            enricher.afterAll(null);
            assertEquals("original", System.getProperty(EXISTING));
            assertNull(System.getProperty(MISSING));
        } finally {
            System.clearProperty(EXISTING);
            System.clearProperty(MISSING);
        }
    }
}
