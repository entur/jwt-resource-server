package org.entur.jwt.junit5.configuration.resolve;

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
		return properties.getProperty(prefix + '.' + id + "." + propertyName);
	}

}
