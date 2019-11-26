package org.entur.jwt.junit5.configuration.enrich;

import java.io.IOException;
import java.util.List;
import java.util.Properties;
import java.util.Set;

import org.entur.jwt.junit5.configuration.resolve.ResourceServerConfiguration;
import org.entur.jwt.junit5.impl.AuthorizationServerImplementation;
import org.junit.jupiter.api.extension.ExtensionContext;

public class SystemPropertiesResourceServerConfigurationEnricher extends AbstractPropertiesResourceServerConfigurationEnricher {

	private Set<String> propertyNames;

	public SystemPropertiesResourceServerConfigurationEnricher() throws IOException {
		super();
	}

	@Override
	public void beforeAll(List<AuthorizationServerImplementation> authorizationServers, ExtensionContext context) throws IOException {
		Properties properties = super.getProperties(authorizationServers);

		propertyNames = properties.stringPropertyNames();
		for (String string : propertyNames) {
			System.setProperty(string, properties.getProperty(string));
		}
	}

	@Override
	public void afterAll(ExtensionContext context) throws IOException {
		if(propertyNames != null) {
			for (String string : propertyNames) {
				System.clearProperty(string);
			}
		}
	}

	@Override
	public void beforeEach(ResourceServerConfiguration configuration, ExtensionContext context) {
		// do nothing
		// TODO generate keys here
	}



}
