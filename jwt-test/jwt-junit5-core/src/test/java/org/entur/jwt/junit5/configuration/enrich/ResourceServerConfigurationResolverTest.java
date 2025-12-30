package org.entur.jwt.junit5.configuration.enrich;

import org.junit.jupiter.api.Test;

import java.util.List;

import static com.google.common.truth.Truth.assertThat;

public class ResourceServerConfigurationResolverTest {

    @Test
    public void testResolvesDummy() {
        List<ResourceServerConfigurationEnricher> load = ResourceServerConfigurationEnricherServiceLoader.load();

        assertThat(load).hasSize(1);
    }
}
