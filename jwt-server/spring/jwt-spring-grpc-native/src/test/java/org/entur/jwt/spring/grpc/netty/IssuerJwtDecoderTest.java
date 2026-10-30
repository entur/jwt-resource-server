package org.entur.jwt.spring.grpc.netty;

import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.util.JSONObjectUtils;
import org.entur.jwt.spring.JwkSourceMap;
import org.entur.jwt.spring.decode.DefaultJwtHeaderToIssuerMapperDecider;
import org.entur.jwt.spring.decode.JwtHeaderToIssuerMapper;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

public class IssuerJwtDecoderTest {

    @Test
    public void testBuilderReturnsFastIssuerDecoderWhenEnabledForMultipleIssuers() throws Exception {
        JwtDecoder decoder = IssuerJwtDecoder.newBuilder()
                .withJwkSourceMap(jwkSourceMapWithTwoIssuers())
                .withJwtValidators(List.of())
                .withMapHeaderToIssuer(true)
                .withJwtHeaderToIssuerMapper(new JwtHeaderToIssuerMapper())
                .withJwtHeaderToIssuerMapperDeciderProvider(new DefaultJwtHeaderToIssuerMapperDecider())
                .build();

        assertThat(decoder).isInstanceOf(FastIssuerJwtDecoder.class);
        FastIssuerJwtDecoder fastDecoder = (FastIssuerJwtDecoder) decoder;
        assertThat(fastDecoder.getMapper().getHeaderToIssuer()).isEmpty();
    }

    @Test
    public void testBuilderReturnsRegularIssuerDecoderWhenDisabledForMultipleIssuers() {
        JwtDecoder decoder = IssuerJwtDecoder.newBuilder()
                .withJwkSourceMap(jwkSourceMapWithTwoIssuers())
                .withJwtValidators(List.of())
                .withMapHeaderToIssuer(false)
                .build();

        assertThat(decoder).isInstanceOf(IssuerJwtDecoder.class);
        assertThat(decoder).isNotInstanceOf(FastIssuerJwtDecoder.class);
    }

    @Test
    public void testFastDecoderCachesHeaderAndUsesFastPath() throws Exception {
        String issuer = "https://issuer-a";
        String validToken = tokenWithIssuer("kid-a", issuer);

        JwtDecoder issuerDecoder = mock(JwtDecoder.class);
        when(issuerDecoder.decode(anyString())).thenReturn(jwt(validToken, issuer, "kid-a"));

        JwtHeaderToIssuerMapper mapper = new JwtHeaderToIssuerMapper();
        FastIssuerJwtDecoder decoder = new FastIssuerJwtDecoder(Map.of(issuer, issuerDecoder), mapper, new DefaultJwtHeaderToIssuerMapperDecider());

        decoder.decode(validToken);

        assertThat(mapper.get(validToken)).isEqualTo(issuer);
        assertThat(mapper.getHeaderToIssuer()).hasSize(1);

        String malformedTokenWithSameHeader = headerSegment(validToken) + ".x";
        decoder.decode(malformedTokenWithSameHeader);

        verify(issuerDecoder).decode(validToken);
        verify(issuerDecoder).decode(malformedTokenWithSameHeader);
        assertThat(mapper.getHeaderToIssuer()).hasSize(1);
    }

    @Test
    public void testFastDecoderDoesNotCacheInvalidTokenHeader() {
        String invalidToken = base64Json(Map.of("alg", "RS256", "kid", "kid-a")) + ".x";

        JwtDecoder issuerDecoder = mock(JwtDecoder.class);
        JwtHeaderToIssuerMapper mapper = new JwtHeaderToIssuerMapper();
        FastIssuerJwtDecoder decoder = new FastIssuerJwtDecoder(Map.of("https://issuer-a", issuerDecoder), mapper, new DefaultJwtHeaderToIssuerMapperDecider());

        assertThatThrownBy(() -> decoder.decode(invalidToken)).isInstanceOf(InvalidBearerTokenException.class);
        assertThat(mapper.getHeaderToIssuer()).isEmpty();
        verifyNoInteractions(issuerDecoder);
    }

    private static JwkSourceMap<?> jwkSourceMapWithTwoIssuers() {
        Map<String, JWKSource<?>> jwkSources = new HashMap<>();
        jwkSources.put("https://issuer-a", mock(JWKSource.class));
        jwkSources.put("https://issuer-b", mock(JWKSource.class));
        return new JwkSourceMap(jwkSources, Map.of());
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
