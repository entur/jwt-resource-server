package org.entur.jwt.spring;

import org.entur.jwt.spring.properties.CorsProperties;
import org.junit.jupiter.api.Test;
import org.springframework.web.cors.CorsConfiguration;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CorsConfigurationFactoryTest {

    private final CorsConfigurationFactory factory = new CorsConfigurationFactory();

    private static CorsProperties properties(String... origins) {
        CorsProperties properties = new CorsProperties();
        properties.setOrigins(List.of(origins));
        return properties;
    }

    @Test
    void allowsCredentialsForOriginsByDefault() {
        CorsConfiguration config = factory.create(properties("https://petstore.swagger.io"));

        assertEquals(List.of("https://petstore.swagger.io"), config.getAllowedOrigins());
        assertNull(config.getAllowedOriginPatterns());
        assertTrue(config.getAllowCredentials());
        assertEquals("https://petstore.swagger.io", config.checkOrigin("https://petstore.swagger.io"));
        assertNull(config.checkOrigin("https://unknown.swagger.io"));
    }

    @Test
    void doesNotAllowCredentialsForAnyOriginByDefault() {
        CorsConfiguration config = factory.create(properties("*"));

        assertEquals(List.of("*"), config.getAllowedOrigins());
        assertFalse(config.getAllowCredentials());
        assertEquals("*", config.checkOrigin("https://petstore.swagger.io"));
    }

    @Test
    void usesOriginPatternsForWildcards() {
        CorsConfiguration config = factory.create(properties("https://petstore.swagger.io", "https://*.entur.org"));

        assertEquals(List.of("https://petstore.swagger.io"), config.getAllowedOrigins());
        assertEquals(List.of("https://*.entur.org"), config.getAllowedOriginPatterns());
        assertTrue(config.getAllowCredentials());
        assertEquals("https://developer.entur.org", config.checkOrigin("https://developer.entur.org"));
        assertEquals("https://petstore.swagger.io", config.checkOrigin("https://petstore.swagger.io"));
        assertNull(config.checkOrigin("https://developer.entur.com"));
    }

    @Test
    void doesNotAllowCredentialsWhenDisabled() {
        CorsProperties properties = properties("https://petstore.swagger.io");
        properties.setAllowCredentials(false);

        CorsConfiguration config = factory.create(properties);

        assertFalse(config.getAllowCredentials());
    }

    @Test
    void doesNotAllowCredentialsForAnyOriginWhenDisabled() {
        CorsProperties properties = properties("*");
        properties.setAllowCredentials(false);

        CorsConfiguration config = factory.create(properties);

        assertFalse(config.getAllowCredentials());
        assertEquals("*", config.checkOrigin("https://petstore.swagger.io"));
    }

    @Test
    void failsWhenCredentialsAreAllowedForAnyOrigin() {
        CorsProperties properties = properties("https://petstore.swagger.io", "*");
        properties.setAllowCredentials(true);

        IllegalStateException e = assertThrows(IllegalStateException.class, () -> factory.create(properties));

        assertTrue(e.getMessage().contains("entur.cors.allow-credentials"));
        assertTrue(e.getMessage().contains("entur.cors.origins"));
    }

    @Test
    void doesNotAllowAnyOriginForWebappMode() {
        CorsProperties properties = properties();
        properties.setMode("webapp");

        CorsConfiguration config = factory.create(properties);

        assertTrue(config.getAllowedOrigins().isEmpty());
        assertNull(config.checkOrigin("https://petstore.swagger.io"));
    }

    @Test
    void failsForOriginsInWebappMode() {
        CorsProperties properties = properties("https://petstore.swagger.io");
        properties.setMode("webapp");

        assertThrows(IllegalStateException.class, () -> factory.create(properties));
    }
}
