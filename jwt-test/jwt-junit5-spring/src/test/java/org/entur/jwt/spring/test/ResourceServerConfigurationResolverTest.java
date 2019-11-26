package org.entur.jwt.spring.test;

import java.util.List;

import org.entur.jwt.junit5.configuration.resolve.ResourceServerConfigurationResolver;
import org.entur.jwt.junit5.configuration.resolve.ResourceServerConfigurationResolverServiceLoader;
import org.junit.jupiter.api.Test;

import static com.google.common.truth.Truth.*;

public class ResourceServerConfigurationResolverTest {

	@Test
	public void testResolvesDummy() {
		List<ResourceServerConfigurationResolver> load = ResourceServerConfigurationResolverServiceLoader.load();

		assertThat(load).hasSize(1);
	}
}
