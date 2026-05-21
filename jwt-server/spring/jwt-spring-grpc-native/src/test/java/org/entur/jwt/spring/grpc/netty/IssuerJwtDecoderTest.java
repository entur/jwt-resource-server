package org.entur.jwt.spring.grpc.netty;

import com.nimbusds.jose.jwk.source.JWKSource;
import org.entur.jwt.spring.JwkSourceMap;
import org.entur.jwt.spring.decode.JwtHeaderToIssuerMapper;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;

import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class IssuerJwtDecoderTest {

    @Test
    public void testBuilderReturnsFastIssuerDecoderWhenEnabledForMultipleIssuers() throws Exception {
        JwtDecoder decoder = IssuerJwtDecoder.newBuilder()
                .withJwkSourceMap(jwkSourceMapWithTwoIssuers())
                .withJwtValidators(List.of())
                .withMapHeaderToIssuer(true)
                .build();

        assertThat(decoder).isInstanceOf(FastIssuerJwtDecoder.class);
        FastIssuerJwtDecoder fastDecoder = (FastIssuerJwtDecoder) decoder;
        assertThat(getHeaderToIssuerState(fastDecoder.getMapper())).isEmpty();
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
        when(issuerDecoder.decode(anyString())).thenReturn(jwt(validToken, issuer));

        JwtHeaderToIssuerMapper mapper = new JwtHeaderToIssuerMapper();
        FastIssuerJwtDecoder decoder = new FastIssuerJwtDecoder(Map.of(issuer, issuerDecoder), mapper);

        decoder.decode(validToken);

        assertThat(mapper.get(validToken)).isEqualTo(issuer);
        assertThat(getHeaderToIssuerState(mapper)).hasSize(1);

        String malformedTokenWithSameHeader = headerSegment(validToken) + ".x";
        decoder.decode(malformedTokenWithSameHeader);

        verify(issuerDecoder).decode(validToken);
        verify(issuerDecoder).decode(malformedTokenWithSameHeader);
        assertThat(getHeaderToIssuerState(mapper)).hasSize(1);
    }

    private static JwkSourceMap<?> jwkSourceMapWithTwoIssuers() {
        Map<String, JWKSource<?>> jwkSources = new HashMap<>();
        jwkSources.put("https://issuer-a", mock(JWKSource.class));
        jwkSources.put("https://issuer-b", mock(JWKSource.class));
        return new JwkSourceMap(jwkSources, Map.of());
    }

    private static Jwt jwt(String token, String issuer) {
        return Jwt.withTokenValue(token)
                .header("alg", "RS256")
                .claim("iss", issuer)
                .issuedAt(Instant.EPOCH)
                .expiresAt(Instant.MAX)
                .build();
    }

    private static String tokenWithIssuer(String kid, String issuer) {
        String header = Base64.getUrlEncoder().withoutPadding().encodeToString(("{\"alg\":\"RS256\",\"kid\":\"" + kid + "\"}").getBytes(StandardCharsets.UTF_8));
        String payload = Base64.getUrlEncoder().withoutPadding().encodeToString(("{\"iss\":\"" + issuer + "\"}").getBytes(StandardCharsets.UTF_8));
        return header + "." + payload + ".signature";
    }

    private static String headerSegment(String token) {
        return token.substring(0, token.indexOf('.'));
    }

    @SuppressWarnings("unchecked")
    private static ConcurrentHashMap<String, String> getHeaderToIssuerState(JwtHeaderToIssuerMapper mapper) throws Exception {
        Field field = JwtHeaderToIssuerMapper.class.getDeclaredField("headerToIssuer");
        field.setAccessible(true);
        return (ConcurrentHashMap<String, String>) field.get(mapper);
    }
}
