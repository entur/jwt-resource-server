package org.entur.jwt.junit5.configuration.resolve;

public interface ResourceServerConfiguration {

    String getProperty(String tenantId, String propertyName);

}
