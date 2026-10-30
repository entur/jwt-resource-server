package org.entur.jwt.junit5.configuration.resolve;

import org.entur.jwt.junit5.impl.AuthorizationServerImplementationFactory;

import java.util.Properties;

public class PropertiesAuthorizationServerConfiguration implements ResourceServerConfiguration {

    private final Properties properties;
    private final String prefix;

    public PropertiesAuthorizationServerConfiguration(String prefix, Properties properties) {
        this.prefix = prefix;
        this.properties = properties;
    }

    @Override
    public String getProperty(String id, String propertyName) {
        if (id == null || id.isEmpty()) {
            // an authorization server without id is written using the on-the-fly id
            String onTheFly = properties.getProperty(prefix + '.' + AuthorizationServerImplementationFactory.ON_THE_FLY_TENANT + "." + propertyName);
            if (onTheFly != null) {
                return onTheFly;
            }
            // if there is only one, select it
            String value = null;
            for (String name : properties.stringPropertyNames()) {
                if (name.startsWith(prefix + '.') && name.endsWith('.' + propertyName)) {
                    if (value != null) {
                        throw new IllegalArgumentException("Authorization server id must be specified in token when using multiple tenants");
                    }
                    value = properties.getProperty(name);
                }
            }
            return value;
        }
        return properties.getProperty(prefix + '.' + id + "." + propertyName);
    }

}
