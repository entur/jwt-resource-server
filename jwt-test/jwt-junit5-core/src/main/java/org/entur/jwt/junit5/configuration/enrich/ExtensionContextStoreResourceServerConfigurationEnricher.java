package org.entur.jwt.junit5.configuration.enrich;

import java.io.IOException;
import java.util.List;

import org.entur.jwt.junit5.configuration.resolve.ResourceServerConfiguration;
import org.entur.jwt.junit5.extention.AuthorizationServerExtension;
import org.entur.jwt.junit5.impl.AuthorizationServerImplementation;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.api.extension.ExtensionContext.Store;

/**
 * 
 * Put authorization servers in JUnit's store.
 *
 */

public class ExtensionContextStoreResourceServerConfigurationEnricher implements ResourceServerConfigurationEnricher {

	protected static final String KEY_AUTHORIZATION_SERVERS = "authorizationServers";
	
	@Override
	public void beforeAll(List<AuthorizationServerImplementation> authorizationServers, ExtensionContext context) throws IOException {
		Store store = AuthorizationServerExtension.getStore(context);
		
		store.put(KEY_AUTHORIZATION_SERVERS, authorizationServers);
	}

	@Override
	public void beforeEach(ResourceServerConfiguration configuration, ExtensionContext context) {
		// do nothing
	}

	@Override
	public void afterAll(ExtensionContext context) throws IOException {
		Store store = AuthorizationServerExtension.getStore(context);
		
		store.remove(KEY_AUTHORIZATION_SERVERS);		
	}

}
