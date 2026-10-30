package org.entur.jwt.junit5.configuration.resolve;

import org.junit.jupiter.api.Test;

import java.nio.file.Paths;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class ResourceServerConfigurationResolverServiceLoaderTest {

    @Test
    public void testPropertiesFileResolverIsLast() {
        ResourceServerConfigurationResolver propertiesFile = new PropertiesFileAuthorizationServerConfigurationResolver(Paths.get("target", "jwt.junit5.properties"), "entur.jwt.tenants");
        // i.e. a framework specific resolver, like for Spring tests
        ResourceServerConfigurationResolver framework = context -> null;
        ResourceServerConfigurationResolver otherFramework = context -> null;

        // the first resolver with a value wins, so framework specific resolvers take precedence
        assertEquals(List.of(framework, otherFramework, propertiesFile), ResourceServerConfigurationResolverServiceLoader.order(List.of(propertiesFile, framework, otherFramework)));
    }
}
