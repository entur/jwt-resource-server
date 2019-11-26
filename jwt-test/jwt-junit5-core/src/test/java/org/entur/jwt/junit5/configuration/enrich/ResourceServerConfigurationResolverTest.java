package org.entur.jwt.junit5.configuration.enrich;

import java.util.List;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import static com.google.common.truth.Truth.*;

public class ResourceServerConfigurationResolverTest {

	@Test
	public void testResolvesDummy() {
		List<ResourceServerConfigurationEnricher> load = ResourceServerConfigurationEnricherServiceLoader.load();

		assertThat(load).hasSize(1);
	}
}
