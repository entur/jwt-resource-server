package org.entur.jwt.spring.grpc.netty;

import org.entur.jwt.spring.grpc.properties.GrpcServicesConfiguration;
import org.entur.jwt.spring.grpc.properties.ServiceMatcherConfiguration;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

public class JwtGrpcAutoConfigurationPermitAllTest {

    @Test
    public void testPermitAllForEnabledServices() {
        GrpcServicesConfiguration grpc = grpc(service("my.Service", true, "unprotected"));

        Map<String, List<String>> mappings = JwtGrpcAutoConfiguration.getPermitAllMappings(grpc);

        assertThat(mappings).containsOnly(Map.entry("my.Service", List.of("unprotected")));
    }

    @Test
    public void testNoPermitAllWhenGrpcPermitAllIsDisabled() {
        GrpcServicesConfiguration grpc = grpc(service("my.Service", true, "*"));
        grpc.setEnabled(false);

        Map<String, List<String>> mappings = JwtGrpcAutoConfiguration.getPermitAllMappings(grpc);

        assertThat(mappings).isEmpty();
    }

    @Test
    public void testNoPermitAllForDisabledOrEmptyServices() {
        GrpcServicesConfiguration grpc = grpc(service("my.DisabledService", false, "*"), service("my.EmptyService", true));

        Map<String, List<String>> mappings = JwtGrpcAutoConfiguration.getPermitAllMappings(grpc);

        assertThat(mappings).isEmpty();
    }

    @Test
    public void testPermitAllMergesServicesWithTheSameName() {
        GrpcServicesConfiguration grpc = grpc(
                service("my.Service", true, "a", "b"),
                service("my.OtherService", true, "c"),
                service("my.Service", true, "b", "d"),
                service("my.Service", false, "e")
        );

        Map<String, List<String>> mappings = JwtGrpcAutoConfiguration.getPermitAllMappings(grpc);

        assertThat(mappings).containsOnly(
                Map.entry("my.Service", List.of("a", "b", "d")),
                Map.entry("my.OtherService", List.of("c"))
        );
    }

    private static GrpcServicesConfiguration grpc(ServiceMatcherConfiguration... services) {
        GrpcServicesConfiguration grpc = new GrpcServicesConfiguration();
        grpc.setServices(new ArrayList<>(List.of(services)));
        return grpc;
    }

    private static ServiceMatcherConfiguration service(String name, boolean enabled, String... methods) {
        ServiceMatcherConfiguration service = new ServiceMatcherConfiguration();
        service.setName(name);
        service.setEnabled(enabled);
        service.setMethods(new ArrayList<>(List.of(methods)));
        return service;
    }
}
