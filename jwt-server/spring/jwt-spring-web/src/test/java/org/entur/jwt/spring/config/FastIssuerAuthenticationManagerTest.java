package org.entur.jwt.spring.config;

import com.nimbusds.jose.util.JSONObjectUtils;
import org.entur.jwt.spring.decode.DefaultJwtHeaderToIssuerMapperDecider;
import org.entur.jwt.spring.decode.JwtHeaderToIssuerMapper;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationManagerResolver;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

public class FastIssuerAuthenticationManagerTest {

    @Test
    public void testAuthenticateCachesMapperStateOnSlowPath() throws Exception {
        String issuer = "https://issuer-a";
        String tokenValue = tokenWithIssuer("kid-a", issuer);

        JwtHeaderToIssuerMapper mapper = new JwtHeaderToIssuerMapper();
        AuthenticationManagerResolver<String> resolver = mock(AuthenticationManagerResolver.class);
        AuthenticationManager delegate = mock(AuthenticationManager.class);

        BearerTokenAuthenticationToken bearerToken = new BearerTokenAuthenticationToken(tokenValue);
        JwtAuthenticationToken jwtAuthentication = new JwtAuthenticationToken(jwt(tokenValue, issuer, "kid-a"));

        when(resolver.resolve(issuer)).thenReturn(delegate);
        when(delegate.authenticate(bearerToken)).thenReturn(jwtAuthentication);

        FastIssuerAuthenticationManager manager = new FastIssuerAuthenticationManager(resolver, mapper, new DefaultJwtHeaderToIssuerMapperDecider());
        Authentication result = manager.authenticate(bearerToken);
        assertThat(result).isSameAs(jwtAuthentication);
        assertThat(mapper.get(tokenValue)).isEqualTo(issuer);
        assertThat(mapper.getHeaderToIssuer()).hasSize(1);
        verify(resolver).resolve(issuer);
        verify(delegate).authenticate(bearerToken);
    }

    @Test
    public void testAuthenticateUsesCachedHeaderMappingOnFastPath() throws Exception {
        String issuer = "https://issuer-a";
        String cachedToken = tokenWithIssuer("kid-a", issuer);
        String malformedTokenWithSameHeader = headerSegment(cachedToken) + ".x";

        JwtHeaderToIssuerMapper mapper = new JwtHeaderToIssuerMapper();
        mapper.add(issuer, cachedToken);

        AuthenticationManagerResolver<String> resolver = mock(AuthenticationManagerResolver.class);
        AuthenticationManager delegate = mock(AuthenticationManager.class);

        BearerTokenAuthenticationToken bearerToken = new BearerTokenAuthenticationToken(malformedTokenWithSameHeader);
        Authentication expected = mock(Authentication.class);

        when(resolver.resolve(issuer)).thenReturn(delegate);
        when(delegate.authenticate(bearerToken)).thenReturn(expected);

        FastIssuerAuthenticationManager manager = new FastIssuerAuthenticationManager(resolver, mapper, new DefaultJwtHeaderToIssuerMapperDecider());
        Authentication result = manager.authenticate(bearerToken);

        assertThat(result).isSameAs(expected);
        assertThat(mapper.getHeaderToIssuer()).hasSize(1);
        verify(resolver).resolve(issuer);
        verify(delegate).authenticate(bearerToken);
    }

    @Test
    public void testAuthenticateDoesNotCacheInvalidTokenHeader() {
        String invalidToken = base64Json(Map.of("alg", "RS256", "kid", "kid-a")) + ".x";

        JwtHeaderToIssuerMapper mapper = new JwtHeaderToIssuerMapper();
        AuthenticationManagerResolver<String> resolver = mock(AuthenticationManagerResolver.class);
        FastIssuerAuthenticationManager manager = new FastIssuerAuthenticationManager(resolver, mapper, new DefaultJwtHeaderToIssuerMapperDecider());

        assertThatThrownBy(() -> manager.authenticate(new BearerTokenAuthenticationToken(invalidToken)))
                .isInstanceOf(InvalidBearerTokenException.class);
        assertThat(mapper.getHeaderToIssuer()).isEmpty();
        verifyNoInteractions(resolver);
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
