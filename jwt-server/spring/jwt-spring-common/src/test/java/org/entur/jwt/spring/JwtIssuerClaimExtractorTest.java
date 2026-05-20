package org.entur.jwt.spring;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;

class JwtIssuerClaimExtractorTest {

    @Test
    void shouldExtractIssuerFromValidToken() {
        String jwt = token("{\"iss\":\"https://issuer.example\",\"sub\":\"a\"}");

        assertThat(JwtIssuerClaimExtractor.extractIssuer(jwt)).isEqualTo("https://issuer.example");
    }

    @Test
    void shouldExtractIssuerWithWhitespaceAndEscapes() {
        String jwt = token("{ \"sub\":\"a\", \"iss\" : \"https:\\/\\/issuer.example\\/tenant\" }");

        assertThat(JwtIssuerClaimExtractor.extractIssuer(jwt)).isEqualTo("https://issuer.example/tenant");
    }

    @Test
    void shouldReturnNullWhenIssuerMissing() {
        String jwt = token("{\"sub\":\"a\"}");

        assertThat(JwtIssuerClaimExtractor.extractIssuer(jwt)).isNull();
    }

    @Test
    void shouldReturnNullForMalformedToken() {
        assertThat(JwtIssuerClaimExtractor.extractIssuer("not-a-jwt")).isNull();
        assertThat(JwtIssuerClaimExtractor.extractIssuer("a.b")).isNull();
    }

    private static String token(String payloadJson) {
        String header = Base64.getUrlEncoder().withoutPadding().encodeToString("{\"alg\":\"none\"}".getBytes(StandardCharsets.UTF_8));
        String payload = Base64.getUrlEncoder().withoutPadding().encodeToString(payloadJson.getBytes(StandardCharsets.UTF_8));
        return header + "." + payload + ".sig";
    }
}
