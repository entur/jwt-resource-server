package org.entur.jwt.junit5.configuration.enrich;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.ServiceLoader;

public class ResourceServerConfigurationEnricherServiceLoader {

	private ResourceServerConfigurationEnricherServiceLoader() {
		// utility method
	}

	public static List<ResourceServerConfigurationEnricher> load() {
		ServiceLoader<ResourceServerConfigurationEnricher> loader = ServiceLoader.load(ResourceServerConfigurationEnricher.class);
		Iterator<ResourceServerConfigurationEnricher> iterator = loader.iterator();

		List<ResourceServerConfigurationEnricher> list = new ArrayList<>();
		while(iterator.hasNext()) {
			list.add(iterator.next());
		}

		return list;		
	}
}
