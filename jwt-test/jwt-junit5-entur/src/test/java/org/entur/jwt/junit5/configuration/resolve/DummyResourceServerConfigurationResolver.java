package org.entur.jwt.junit5.configuration.resolve;

import org.junit.jupiter.api.extension.ExtensionContext;

public class DummyResourceServerConfigurationResolver implements ResourceServerConfigurationResolver, ResourceServerConfiguration {

    @Override
    public String getProperty(String id, String propertyName) {
        if (id == null || id.isEmpty()) {
            return "dummy-" + propertyName;
        }
        return "dummy-" + id + "-" + propertyName;
    }

    @Override
    public ResourceServerConfiguration resolve(ExtensionContext context) throws Exception {
        return this;
    }

}
