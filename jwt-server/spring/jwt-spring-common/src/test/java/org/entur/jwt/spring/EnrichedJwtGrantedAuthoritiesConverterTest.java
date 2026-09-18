package org.entur.jwt.spring;

import org.junit.jupiter.api.Test;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

import java.time.Instant;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class EnrichedJwtGrantedAuthoritiesConverterTest {

    private Jwt jwt() {
        Map<String, Object> headers = Collections.singletonMap("alg", "none");
        Map<String, Object> claims = Collections.singletonMap("sub", "subject");
        return new Jwt("token", Instant.now(), Instant.now().plusSeconds(60), headers, claims);
    }

    @Test
    void appliesAllEnrichersInOrder() {
        JwtAuthorityEnricher first = (current, jwt) -> current.add(new SimpleGrantedAuthority("FIRST"));
        JwtAuthorityEnricher second = (current, jwt) -> current.add(new SimpleGrantedAuthority("SECOND"));

        EnrichedJwtGrantedAuthoritiesConverter converter = new EnrichedJwtGrantedAuthoritiesConverter(List.of(first, second));

        Collection<GrantedAuthority> authorities = converter.convert(jwt());

        assertEquals(List.of("FIRST", "SECOND"), authorities.stream().map(GrantedAuthority::getAuthority).toList());
    }

    @Test
    void returnsEmptyCollectionWhenNoEnrichers() {
        EnrichedJwtGrantedAuthoritiesConverter converter = new EnrichedJwtGrantedAuthoritiesConverter(List.of());

        Collection<GrantedAuthority> authorities = converter.convert(jwt());

        assertTrue(authorities.isEmpty());
    }
}
