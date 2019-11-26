package org.entur.jwt.spring.test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashSet;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import org.entur.jwt.junit5.extention.AuthorizationServerExtension;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.env.EnvironmentPostProcessor;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.MapPropertySource;
import org.springframework.core.env.MutablePropertySources;
import org.springframework.core.env.PropertySource;
import org.springframework.core.io.support.ResourcePropertySource;

/**
 * 
 * Class for injecting manipulated properties into the Spring context.
 * 
 * This class always fires; ignore it if no properties file exists.
 * 
 */

@Order(Ordered.LOWEST_PRECEDENCE)
public class JwtEnvironmentPostProcessor implements EnvironmentPostProcessor {
 
	public static final String PROPERTY_PREFIX = "entur.jwt.tenants.";
	public static final String PROPERTY_SOURCE_NAME = "jwtJunit5Properties";

    @Override
    public void postProcessEnvironment(ConfigurableEnvironment environment, SpringApplication application) {
    	try {
    		Path path = Paths.get("jwt.junit5.properties");
    		if(Files.exists(path)) {
				ResourcePropertySource source = new ResourcePropertySource("file:jwt.junit5.properties");
				
				Map<String, Object> junit5Properties = source.getSource();
				// see whether issuer is populated, if not create a mock value
				// background: JWTs need an issuer, so using a list would be the easy way. 
				// But configuration manipulation
				// is generally better when specifying tenants under an id key 
				// This approach works around this.
				
				Set<String> tenants = extractTenants(junit5Properties); 
				
				for(String tenant: tenants) {
					String property = environment.getProperty(tenant + ".issuer");
					if(property == null) {
						// add mock issuer url
						String mockIssuer = AuthorizationServerExtension.toDefaultIssuer(tenant.substring(tenant.lastIndexOf('.') + 1));
						junit5Properties.put(tenant + ".issuer", mockIssuer);
					}
				}
				
				addOrReplace(environment.getPropertySources(), junit5Properties);
    		}
		} catch (IOException e) {
			throw new IllegalStateException("Unable to load properties", e);
		}
    }

	private Set<String> extractTenants(Map<String, Object> junit5Properties) {
		Set<String> tenant = new HashSet<>();
		
		for (Entry<String, Object> entry : junit5Properties.entrySet()) {
			
			String key = entry.getKey();
			if(key.startsWith(PROPERTY_PREFIX)) {
				int nextDot = key.indexOf('.', PROPERTY_PREFIX.length());
				if(nextDot != -1) {
					tenant.add(key.substring(0, nextDot));
				}
			}
		}
		
		
		return tenant;
	}

	private void addOrReplace(MutablePropertySources propertySources, Map<String, Object> map) {
		MapPropertySource target = null;
		if (propertySources.contains(PROPERTY_SOURCE_NAME)) {
			PropertySource<?> source = propertySources.get(PROPERTY_SOURCE_NAME);
			if (source instanceof MapPropertySource) {
				target = (MapPropertySource) source;
				for (Entry<String, Object> entry : map.entrySet()) {
					if (!target.containsProperty(entry.getKey())) {
						target.getSource().put(entry.getKey(), entry.getValue());
					}
				}
			}
		}
		if (target == null) {
			target = new MapPropertySource(PROPERTY_SOURCE_NAME, map);
		}
		if (!propertySources.contains(PROPERTY_SOURCE_NAME)) {
			propertySources.addFirst(target);
		}
	}    
}