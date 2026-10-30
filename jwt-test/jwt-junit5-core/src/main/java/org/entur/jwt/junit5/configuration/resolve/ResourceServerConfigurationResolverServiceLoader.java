package org.entur.jwt.junit5.configuration.resolve;

import java.util.ArrayList;
import java.util.Comparator;
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
        while (iterator.hasNext()) {
            list.add(iterator.next());
        }

        return order(list);
    }

    /**
     * Order the resolvers so that the properties file resolver, which applies to any test, comes last: the first
     * resolver with a value wins, so framework specific resolvers (i.e. for Spring tests) take precedence.
     *
     * @param resolvers resolvers
     * @return the resolvers, with any properties file resolver last
     */

    public static List<ResourceServerConfigurationResolver> order(List<ResourceServerConfigurationResolver> resolvers) {
        List<ResourceServerConfigurationResolver> ordered = new ArrayList<>(resolvers);
        ordered.sort(Comparator.comparing(PropertiesFileAuthorizationServerConfigurationResolver.class::isInstance));
        return ordered;
    }
}
