package org.entur.jwt.junit5.configuration.resolve;

import org.junit.jupiter.api.Test;

import java.util.List;

import static com.google.common.truth.Truth.assertThat;

public class ResourceServerConfigurationResolverTest {

    @Test
    public void testResolvesDummy() {
        List<ResourceServerConfigurationResolver> load = ResourceServerConfigurationResolverServiceLoader.load();

        assertThat(load).hasSize(0);
    }
}
