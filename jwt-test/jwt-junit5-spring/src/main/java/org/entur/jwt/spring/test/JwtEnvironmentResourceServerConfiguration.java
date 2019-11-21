package org.entur.jwt.spring.test;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.StreamSupport;

import org.entur.jwt.junit5.configuration.resolve.ResourceServerConfiguration;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.EnumerablePropertySource;
import org.springframework.core.env.Environment;
import org.springframework.core.env.MutablePropertySources;

public class JwtEnvironmentResourceServerConfiguration implements ResourceServerConfiguration {

	private final Environment environment;
	private final String prefix;
	
	public JwtEnvironmentResourceServerConfiguration(Environment environment, String prefix) {
		super();
		this.environment = environment;
		this.prefix = prefix;
	}

	@Override
	public String getProperty(String id, String propertyName) {
		if(id == null || id.isEmpty()) {
			// if there is only one, select it
			if(environment instanceof ConfigurableEnvironment) {
				ConfigurableEnvironment configurableEnvironment = (ConfigurableEnvironment)environment;
				
				MutablePropertySources propertySources = configurableEnvironment.getPropertySources();
				
				Map<String, String> props = new HashMap<>();
				StreamSupport.stream(propertySources.spliterator(), false)
				        .filter(ps -> ps instanceof EnumerablePropertySource)
				        .map(ps -> ((EnumerablePropertySource<?>) ps).getPropertyNames())
				        .flatMap(Arrays::<String>stream)
				        .filter(name -> name.startsWith(prefix))
				        .filter(name -> name.endsWith("." + propertyName))
				        .forEach(propName -> props.put(propName, environment.getProperty(propName, String.class)));				
				if(props.size() == 1) {
					return props.entrySet().iterator().next().getValue();
				} else {
					throw new IllegalArgumentException("Authorization server id must be specified in token when using multiple ( " + props.size() + ") tenants (either mocks or configured)");
				}
			}
		}
		return environment.getProperty(prefix + '.' + id +"." + propertyName);
	}
}
