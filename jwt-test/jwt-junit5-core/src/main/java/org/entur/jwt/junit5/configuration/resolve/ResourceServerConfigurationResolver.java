package org.entur.jwt.junit5.configuration.resolve;

import org.junit.jupiter.api.extension.ExtensionContext;

/**
 * 
 * Interface for resolving (canonical) configuration. For configuration we're
 * not overriding, but need to take into account when mocking the authorization
 * server.
 * 
 */

public interface ResourceServerConfigurationResolver {

    /**
     * Resolve resource server configuration.
     *
     * @param context extension context
     * @return configuration, or null if not applicable for the current test
     * @throws Exception if the configuration could not be resolved
     */

    ResourceServerConfiguration resolve(ExtensionContext context) throws Exception;

}
