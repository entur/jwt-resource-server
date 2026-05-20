package org.entur.jwt.spring;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;

class JwtHeaderKidExtractorTest {

    @Test
    void shouldExtractKidFromHeader() {
        String jwt = token("{\"iss\":\"https://issuer.example\"}", "{\"alg\":\"RS256\",\"kid\":\"kid-123\"}");

        assertThat(JwtHeaderKidExtractor.extractKid(jwt)).isEqualTo("kid-123");
    }

    @Test
    void shouldReturnNullForMissingKidOrMalformedToken() {
        assertThat(JwtHeaderKidExtractor.extractKid(token("{\"iss\":\"https://issuer.example\"}", "{\"alg\":\"RS256\"}"))).isNull();
        assertThat(JwtHeaderKidExtractor.extractKid("bad-token")).isNull();
    }

    private static String token(String payloadJson, String headerJson) {
        String header = Base64.getUrlEncoder().withoutPadding().encodeToString(headerJson.getBytes(StandardCharsets.UTF_8));
        String payload = Base64.getUrlEncoder().withoutPadding().encodeToString(payloadJson.getBytes(StandardCharsets.UTF_8));
        return header + "." + payload + ".sig";
    }
}
