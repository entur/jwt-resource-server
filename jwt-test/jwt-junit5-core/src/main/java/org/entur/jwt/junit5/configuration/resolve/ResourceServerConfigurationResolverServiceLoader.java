package org.entur.jwt.junit5.configuration.resolve;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.ServiceLoader;

public class ResourceServerConfigurationResolverServiceLoader {

	private ResourceServerConfigurationResolverServiceLoader() {
		// utility class
	}
	
	public static List<ResourceServerConfigurationResolver> load() {
		ServiceLoader<ResourceServerConfigurationResolver> loader = ServiceLoader.load(ResourceServerConfigurationResolver.class);
		Iterator<ResourceServerConfigurationResolver> iterator = loader.iterator();
		
		List<ResourceServerConfigurationResolver> list = new ArrayList<>();
		while(iterator.hasNext()) {
			list.add(iterator.next());
		}
		
		return list;		
	}
}
