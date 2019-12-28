package org.entur.jwt.spring.test;

import java.util.HashMap;
import java.util.Map;

import org.entur.jwt.junit5.configuration.resolve.ResourceServerConfiguration;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.EnumerablePropertySource;
import org.springframework.core.env.Environment;
import org.springframework.core.env.MutablePropertySources;
import org.springframework.core.env.PropertySource;

public class JwtEnvironmentResourceServerConfiguration implements ResourceServerConfiguration {

    private final Environment environment;
    private final String prefix;
    private final String enabled;

    public JwtEnvironmentResourceServerConfiguration(Environment environment, String propertyPrefix, String enabledPropertyName) {
        super();
        this.environment = environment;
        this.prefix = propertyPrefix;
        this.enabled = enabledPropertyName;
    }

    @Override
    public String getProperty(String id, String propertyName) {
        if (id == null || id.isEmpty()) {
            // if there is only one, select it
            if (environment instanceof ConfigurableEnvironment) {
                ConfigurableEnvironment configurableEnvironment = (ConfigurableEnvironment) environment;

                MutablePropertySources propertySources = configurableEnvironment.getPropertySources();

                Map<String, String> props = extractEnabled(propertySources, propertyName);
                if (props.size() == 1) {
                    return props.entrySet().iterator().next().getValue();
                } else {
                    throw new IllegalArgumentException("Authorization server id must be specified in token when using multiple (" + props.size() + ") tenants");
                }
            }
        }
        return environment.getProperty(prefix + '.' + id + "." + propertyName);
    }

    public Map<String, String> extractEnabled(MutablePropertySources sources, String propertyName) {
        Map<String, String> props = new HashMap<>();

        for(PropertySource<?> propertySource : sources) {
            if(propertySource instanceof EnumerablePropertySource) {
                EnumerablePropertySource<?> epSource = (EnumerablePropertySource<?>)propertySource;
                
                for(String name : epSource.getPropertyNames()) {
                    if (name.startsWith(prefix) && name.endsWith(propertyName)) {
                        int index = name.indexOf('.', prefix.length() + 1);
                        
                        String enabler = name.substring(0, index) + enabled;
                        String nullOrEnabled = environment.getProperty(enabler, String.class);
                        if(nullOrEnabled == null || !nullOrEnabled.equals("false")) {
                            props.put(name, environment.getProperty(name, String.class));
                        }
                    }
                }
            }
        }
        
        return props;
    }      
}
