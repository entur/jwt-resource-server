package org.entur.jwt.junit5.configuration.enrich;

import org.junit.jupiter.api.parallel.ResourceAccessMode;
import org.junit.jupiter.api.parallel.ResourceLocksProvider;
import org.junit.jupiter.api.parallel.Resources;

import java.util.List;
import java.util.Set;

/**
 * {@link SystemPropertiesResourceServerConfigurationEnricher} sets (and later restores) JVM-wide system properties, so
 * test classes using it must not run in parallel with each other, or with other tests accessing system properties.
 * Other test classes (i.e. Spring tests) are not affected.
 */

public class SystemPropertiesResourceLocksProvider implements ResourceLocksProvider {

    public static final String RESOURCE = Resources.SYSTEM_PROPERTIES;

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
        if (isSystemProperties()) {
            return Set.of(new Lock(RESOURCE, ResourceAccessMode.READ_WRITE));
        }
        return Set.of();
    }

    protected boolean isSystemProperties() {
        return ResourceServerConfigurationEnricherServiceLoader.load().stream().anyMatch(SystemPropertiesResourceServerConfigurationEnricher.class::isInstance);
    }
}
