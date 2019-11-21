package org.entur.jwt.junit5.configuration.resolve;

import org.junit.jupiter.api.extension.ExtensionContext;

/**
 * 
 * Interface for resolving (canonical) configuration. For configuration we're not overriding, but need to  
 * take into account when mocking the authorization server.
 * 
 */

public interface ResourceServerConfigurationResolver  {

	ResourceServerConfiguration resolve(ExtensionContext context) throws Exception;

}
