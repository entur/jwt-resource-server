package org.entur.jwt.spring.test;

import org.entur.jwt.junit5.configuration.enrich.ResourceServerConfigurationEnricher;
import org.entur.jwt.junit5.configuration.resolve.ResourceServerConfiguration;
import org.entur.jwt.junit5.impl.AuthorizationServerImplementation;
import org.junit.jupiter.api.extension.ExtensionContext;

import java.io.IOException;
import java.util.List;

// https://docs.spring.io/spring/docs/current/spring-framework-reference/testing.html#testcontext-ctx-management

public class SpringTestResourceServerConfigurationEnricher implements ResourceServerConfigurationEnricher {

    public SpringTestResourceServerConfigurationEnricher() throws IOException {
        super();
    }

    @Override
    public void beforeAll(List<AuthorizationServerImplementation> authorizationServers, ExtensionContext context) throws IOException {
        // do nothing
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
