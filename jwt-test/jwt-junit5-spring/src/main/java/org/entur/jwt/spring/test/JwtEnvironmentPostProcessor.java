package org.entur.jwt.spring.test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashSet;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.entur.jwt.junit5.extention.AuthorizationServerExtension;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.env.EnvironmentPostProcessor;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.EnumerablePropertySource;
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

    private static final Log logger = LogFactory.getLog(JwtEnvironmentPostProcessor.class);
    
    public static final String PROPERTY_PREFIX = "entur.jwt.tenants.";
    public static final String PROPERTY_SOURCE_NAME = "jwtJunit5Properties";

    public static final String ON_THE_FLY_PROPERTY = ".on-the-fly";

    @Override
    public void postProcessEnvironment(ConfigurableEnvironment environment, SpringApplication application) {
        try {
            Path path = Paths.get("jwt.junit5.properties");
            if (Files.exists(path)) {
                ResourcePropertySource source = new ResourcePropertySource("file:jwt.junit5.properties");

                Map<String, Object> junit5Properties = source.getSource();
                // see whether issuer is populated, if not create a mock value
                // background: JWTs need an issuer, so using a list would be the easy way.
                // But configuration manipulation
                // is generally better when specifying tenants under an id key
                // This approach works around this.

                Set<String> tenants = extractTenants(junit5Properties);
                Set<String> configuredTentants = extractConfiguredTenants(environment.getPropertySources());

                if(tenants.size() == 1 && configuredTentants.size() == 1) {
                    // if only one mocked and one configured tenant
                    // and no name for the mocked tenant was specified (i.e. its key was created on the fly)
                    // then simplyify so that the configured tenant is mocked
                    String mocked = tenants.iterator().next();
                    String onTheFly = (String) junit5Properties.get(mocked + ON_THE_FLY_PROPERTY);
                    if(onTheFly != null && Boolean.parseBoolean(onTheFly)) {
                        // mock the configured one instead
                        // TODO the mocked tenant will still have the on-the-fly name within the junit5 extension
                        String target = configuredTentants.iterator().next();
                        for (String string : new HashSet<>(junit5Properties.keySet())) {
                            if(string.startsWith(mocked)) {
                                String value = (String) junit5Properties.remove(string);

                                junit5Properties.put(target + string.substring(mocked.length()), value);
                            }
                        }
                        tenants = new HashSet<>();
                        tenants.add(target);
                    }
                }

                for (String string : new HashSet<>(junit5Properties.keySet())) {
                    if(string.endsWith(ON_THE_FLY_PROPERTY)) {
                        junit5Properties.remove(string);
                    }
                }
                // make sure that there is no mix of mocked and non-mocked issuers
                if(!tenants.containsAll(configuredTentants)) {
                    configuredTentants.removeAll(tenants);
                    
                    logger.info("Disabling non-mocked tenants " + configuredTentants);

                    // disable non-mocked tenants
                    for (String tenant : configuredTentants) {
                        junit5Properties.put(tenant + ".enabled", Boolean.FALSE.toString());
                    }
                }

                for (String tenant : tenants) {
                    String property = environment.getProperty(tenant + ".issuer");
                    if (property == null) {
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
            if (key.startsWith(PROPERTY_PREFIX)) {
                int nextDot = key.indexOf('.', PROPERTY_PREFIX.length());
                if (nextDot != -1) {
                    tenant.add(key.substring(0, nextDot));
                }
            }
        }

        return tenant;
    }
    
    private Set<String> extractConfiguredTenants(MutablePropertySources sources) {
        Set<String> tenant = new HashSet<>();

        for(PropertySource<?> propertySource : sources) {
            if(propertySource instanceof EnumerablePropertySource) {
                EnumerablePropertySource<?> epSource = (EnumerablePropertySource<?>)propertySource;
                
                for(String name : epSource.getPropertyNames()) {
                    if (hasPropertyPrefix(name)) {
                        tenant.add(parseFirstPropertyName(name));
                    }
                }
            }
        }
        
        return tenant;
    }

	private String parseFirstPropertyName(String name) {
		int index = name.indexOf('.', PROPERTY_PREFIX.length());
		String result;
		if(index == -1) {
			result = name;
		} else {
			result = name.substring(0, index);
		}
		return result;
	}

	private boolean hasPropertyPrefix(String name) {
		return name.startsWith(PROPERTY_PREFIX) && name.length() > PROPERTY_PREFIX.length();
	}    

    private void addOrReplace(MutablePropertySources propertySources, Map<String, Object> map) {
        PropertySource<?> source = propertySources.get(PROPERTY_SOURCE_NAME);
        if (source != null) {
            MapPropertySource target = (MapPropertySource) source;
            target.getSource().putAll(map);
        } else {
            MapPropertySource target = new MapPropertySource(PROPERTY_SOURCE_NAME, map);
            propertySources.addFirst(target);
        }
    }
}