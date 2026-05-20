package org.entur.jwt.spring;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class JwtIssuerBase64MatcherTest {

    @Test
    void shouldMatchIssuerForAllBase64AlignmentOffsets() {
        JwtIssuerBase64Matcher matcher = new JwtIssuerBase64Matcher(List.of("https://issuer-2.example"));

        assertThat(matcher.matchIssuerFromToken(token("{\"iss\":\"https://issuer-2.example\",\"sub\":\"a\"}")))
                .isEqualTo("https://issuer-2.example");
        assertThat(matcher.matchIssuerFromToken(token("{\"x\":\"1\",\"iss\":\"https://issuer-2.example\",\"sub\":\"a\"}")))
                .isEqualTo("https://issuer-2.example");
        assertThat(matcher.matchIssuerFromToken(token("{\"xy\":\"1\",\"iss\":\"https://issuer-2.example\",\"sub\":\"a\"}")))
                .isEqualTo("https://issuer-2.example");
    }

    @Test
    void shouldReturnNullWhenNoConfiguredIssuerMatches() {
        JwtIssuerBase64Matcher matcher = new JwtIssuerBase64Matcher(List.of("https://issuer-1.example"));

        assertThat(matcher.matchIssuerFromToken(token("{\"iss\":\"https://issuer-2.example\"}"))).isNull();
    }

    private static String token(String payloadJson) {
        String header = Base64.getUrlEncoder().withoutPadding().encodeToString("{\"alg\":\"none\"}".getBytes(StandardCharsets.UTF_8));
        String payload = Base64.getUrlEncoder().withoutPadding().encodeToString(payloadJson.getBytes(StandardCharsets.UTF_8));
        return header + "." + payload + ".sig";
    }
}
