package org.entur.jwt.junit5.configuration.enrich;

import org.entur.jwt.junit5.configuration.resolve.ResourceServerConfiguration;
import org.entur.jwt.junit5.extension.AuthorizationServerExtension;
import org.entur.jwt.junit5.impl.AuthorizationServerImplementation;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.api.extension.ExtensionContext.Store;

import java.io.IOException;
import java.util.List;

/**
 * 
 * Put authorization servers in JUnit's store, in the store of the extension context of each test class (under the
 * namespace {@link AuthorizationServerExtension#NAMESPACE}). A {@literal @}Nested test class has its own entry,
 * so a test (or test class) finds the authorization servers of its own test class, also when test classes run in parallel.
 *
 */

public class ExtensionContextStoreResourceServerConfigurationEnricher implements ResourceServerConfigurationEnricher {

    protected static final String KEY_AUTHORIZATION_SERVERS = "authorizationServers";

    @Override
    public void beforeAll(List<AuthorizationServerImplementation> authorizationServers, ExtensionContext context) throws IOException {
        Store store = getStore(context);

        store.put(KEY_AUTHORIZATION_SERVERS, authorizationServers);
    }

    @Override
    public void beforeEach(ResourceServerConfiguration configuration, ExtensionContext context) {
        // do nothing
    }

    @Override
    public void afterAll(ExtensionContext context) throws IOException {
        Store store = getStore(context);

        // only removes the entry of this context, not that of an enclosing test class
        store.remove(KEY_AUTHORIZATION_SERVERS);
    }

    // not the root store, as that is shared by all test classes
    private static Store getStore(ExtensionContext context) {
        return context.getStore(AuthorizationServerExtension.NAMESPACE);
    }

}
