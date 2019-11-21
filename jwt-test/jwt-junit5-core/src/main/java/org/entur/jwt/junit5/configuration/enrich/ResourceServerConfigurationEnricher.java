package org.entur.jwt.junit5.configuration.enrich;

import java.io.IOException;
import java.util.List;

import org.entur.jwt.junit5.configuration.resolve.ResourceServerConfiguration;
import org.entur.jwt.junit5.impl.AuthorizationServerImplementation;
import org.junit.jupiter.api.extension.ExtensionContext;

public interface ResourceServerConfigurationEnricher  {

	void beforeAll(List<AuthorizationServerImplementation> authorizationServers, ExtensionContext context) throws IOException; 
	
	void beforeEach(ResourceServerConfiguration configuration, ExtensionContext context);
	
	void afterAll(ExtensionContext context) throws IOException;
}
