package org.entur.jwt.junit5.configuration.enrich;

import org.junit.jupiter.api.parallel.ResourceAccessMode;
import org.junit.jupiter.api.parallel.ResourceLocksProvider;

import java.util.List;
import java.util.Set;

/**
 * Test classes using {@link PropertiesFileResourceServerConfigurationEnricher} share a single properties file,
 * so do not run them in parallel with each other. Other test classes (i.e. Spring tests) are not affected.
 */

public class PropertiesFileResourceLocksProvider implements ResourceLocksProvider {

    public static final String RESOURCE = PropertiesFileResourceServerConfigurationEnricher.class.getName();

    private static volatile Boolean propertiesFile;

    @Override
    public Set<Lock> provideForClass(Class<?> testClass) {
        return getLocks();
    }

    // i.e. a @Nested test class with authorization servers, within a test class without
    @Override
    public Set<Lock> provideForNestedClass(List<Class<?>> enclosingInstanceTypes, Class<?> testClass) {
        return getLocks();
    }

    protected Set<Lock> getLocks() {
        if (isPropertiesFile()) {
            return Set.of(new Lock(RESOURCE, ResourceAccessMode.READ_WRITE));
        }
        return Set.of();
    }

    protected static boolean isPropertiesFile() {
        Boolean value = propertiesFile;
        if (value == null) {
            value = ResourceServerConfigurationEnricherServiceLoader.load().stream().anyMatch(PropertiesFileResourceServerConfigurationEnricher.class::isInstance);
            propertiesFile = value;
        }
        return value;
    }
}
