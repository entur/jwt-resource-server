package org.entur.jwt.spring.decode;

import com.nimbusds.jose.util.JSONObjectUtils;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

public class IssuerJwtDecoderTest {

    @Test
    public void testFastDecoderCachesHeaderAndUsesFastPath() throws Exception {
        String issuer = "https://issuer-a";
        String validToken = tokenWithIssuer("kid-a", issuer);

        List<String> decoded = new ArrayList<>();
        JwtDecoder issuerDecoder = token -> {
            decoded.add(token);
            return jwt(validToken, issuer, "kid-a");
        };

        JwtHeaderToIssuerMapper mapper = new JwtHeaderToIssuerMapper();
        FastIssuerJwtDecoder decoder = new FastIssuerJwtDecoder(Map.of(issuer, issuerDecoder), mapper, new DefaultJwtHeaderToIssuerMapperDecider());

        decoder.decode(validToken);

        assertThat(mapper.get(validToken)).isEqualTo(issuer);
        assertThat(mapper.getHeaderToIssuer()).hasSize(1);

        String malformedTokenWithSameHeader = headerSegment(validToken) + ".x";
        decoder.decode(malformedTokenWithSameHeader);

        assertThat(decoded).containsExactly(validToken, malformedTokenWithSameHeader);
        assertThat(mapper.getHeaderToIssuer()).hasSize(1);
    }

    @Test
    public void testFastDecoderDoesNotCacheInvalidTokenHeader() {
        String invalidToken = base64Json(Map.of("alg", "RS256", "kid", "kid-a")) + ".x";

        List<String> decoded = new ArrayList<>();
        JwtDecoder issuerDecoder = token -> {
            decoded.add(token);
            throw new IllegalStateException("Not expected");
        };
        JwtHeaderToIssuerMapper mapper = new JwtHeaderToIssuerMapper();
        FastIssuerJwtDecoder decoder = new FastIssuerJwtDecoder(Map.of("https://issuer-a", issuerDecoder), mapper, new DefaultJwtHeaderToIssuerMapperDecider());

        assertThatThrownBy(() -> decoder.decode(invalidToken)).isInstanceOf(InvalidBearerTokenException.class);
        assertThat(mapper.getHeaderToIssuer()).isEmpty();
        assertThat(decoded).isEmpty();
    }

    private static Jwt jwt(String token, String issuer, String kid) {
        return Jwt.withTokenValue(token)
                .header("alg", "RS256")
                .header("kid", kid)
                .claim("iss", issuer)
                .issuedAt(Instant.EPOCH)
                .expiresAt(Instant.MAX)
                .build();
    }

    private static String tokenWithIssuer(String kid, String issuer) {
        String header = base64Json(Map.of("alg", "RS256", "kid", kid));
        String payload = base64Json(Map.of("iss", issuer));
        return header + "." + payload + ".signature";
    }

    private static String headerSegment(String token) {
        return token.substring(0, token.indexOf('.'));
    }

    private static String base64Json(Map<String, ?> claims) {
        return Base64.getUrlEncoder().withoutPadding()
                .encodeToString(JSONObjectUtils.toJSONString(claims).getBytes(StandardCharsets.UTF_8));
    }
}
