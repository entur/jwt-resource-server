package org.entur.jwt.spring.filter.log;

import org.entur.jwt.spring.properties.MdcPair;
import org.entur.jwt.spring.properties.MdcProperties;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.Jwt;

import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JwtMappedDiagnosticContextMapperFactoryTest {

    private static MdcPair pair(String from, String to) {
        MdcPair pair = new MdcPair();
        pair.setFrom(from);
        pair.setTo(to);
        return pair;
    }

    @Test
    void buildsMapperFromConfiguredMappings() {
        MdcProperties properties = new MdcProperties();
        properties.setMappings(List.of(pair("sub", "userId"), pair("tenant", "tenantId")));

        JwtMappedDiagnosticContextMapperFactory factory = new JwtMappedDiagnosticContextMapperFactory();
        JwtMappedDiagnosticContextMapper mapper = factory.mapper(properties);

        Map<String, Object> headers = Collections.singletonMap("alg", "none");
        Map<String, Object> claims = Map.of("sub", "user-1", "tenant", "tenant-1");
        Jwt jwt = new Jwt("token", Instant.now(), Instant.now().plusSeconds(60), headers, claims);

        Map<String, String> context = mapper.getContext(jwt);

        assertEquals("user-1", context.get("userId"));
        assertEquals("tenant-1", context.get("tenantId"));
        assertEquals(2, context.size());
    }

    @Test
    void buildsEmptyMapperWhenNoMappingsConfigured() {
        MdcProperties properties = new MdcProperties();

        JwtMappedDiagnosticContextMapperFactory factory = new JwtMappedDiagnosticContextMapperFactory();
        JwtMappedDiagnosticContextMapper mapper = factory.mapper(properties);

        Map<String, Object> headers = Collections.singletonMap("alg", "none");
        Map<String, Object> claims = Collections.singletonMap("sub", "user-1");
        Jwt jwt = new Jwt("token", Instant.now(), Instant.now().plusSeconds(60), headers, claims);

        assertTrue(mapper.getContext(jwt).isEmpty());
    }
}
