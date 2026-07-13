package org.entur.jwt.spring.config;

import com.nimbusds.jose.util.JSONObjectUtils;
import org.entur.jwt.spring.decode.DefaultJwtHeaderToIssuerMapperDecider;
import org.entur.jwt.spring.decode.JwtHeaderToIssuerMapper;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

public class FastReactiveIssuerAuthenticationManagerTest {

    @Test
    public void testAuthenticateCachesMapperStateOnSlowPath() {
        String issuer = "https://issuer-a";
        String tokenValue = tokenWithIssuer("kid-a", issuer);

        JwtHeaderToIssuerMapper mapper = new JwtHeaderToIssuerMapper();
        IssuerAuthenticationManagerResolver resolver = mock(IssuerAuthenticationManagerResolver.class);
        ReactiveAuthenticationManager delegate = mock(ReactiveAuthenticationManager.class);

        BearerTokenAuthenticationToken bearerToken = new BearerTokenAuthenticationToken(tokenValue);
        JwtAuthenticationToken jwtAuthentication = new JwtAuthenticationToken(jwt(tokenValue, issuer, "kid-a"));

        when(resolver.resolve(issuer)).thenReturn(Mono.just(delegate));
        when(delegate.authenticate(bearerToken)).thenReturn(Mono.just(jwtAuthentication));

        FastReactiveIssuerAuthenticationManager manager = new FastReactiveIssuerAuthenticationManager(resolver, mapper, new DefaultJwtHeaderToIssuerMapperDecider());
        Authentication result = manager.authenticate(bearerToken).block();

        assertThat(result).isSameAs(jwtAuthentication);
        assertThat(mapper.get(tokenValue)).isEqualTo(issuer);
        assertThat(mapper.getHeaderToIssuer()).hasSize(1);
        verify(resolver).resolve(issuer);
        verify(delegate).authenticate(bearerToken);
    }

    @Test
    public void testAuthenticateUsesCachedHeaderMappingOnFastPath() {
        String issuer = "https://issuer-a";
        String cachedToken = tokenWithIssuer("kid-a", issuer);
        String malformedTokenWithSameHeader = headerSegment(cachedToken) + ".x";

        JwtHeaderToIssuerMapper mapper = new JwtHeaderToIssuerMapper();
        mapper.add(issuer, cachedToken);

        IssuerAuthenticationManagerResolver resolver = mock(IssuerAuthenticationManagerResolver.class);
        ReactiveAuthenticationManager delegate = mock(ReactiveAuthenticationManager.class);

        BearerTokenAuthenticationToken bearerToken = new BearerTokenAuthenticationToken(malformedTokenWithSameHeader);
        Authentication expected = mock(Authentication.class);

        when(resolver.resolve(issuer)).thenReturn(Mono.just(delegate));
        when(delegate.authenticate(bearerToken)).thenReturn(Mono.just(expected));

        FastReactiveIssuerAuthenticationManager manager = new FastReactiveIssuerAuthenticationManager(resolver, mapper, new DefaultJwtHeaderToIssuerMapperDecider());
        Authentication result = manager.authenticate(bearerToken).block();

        assertThat(result).isSameAs(expected);
        assertThat(mapper.getHeaderToIssuer()).hasSize(1);
        verify(resolver).resolve(issuer);
        verify(delegate).authenticate(bearerToken);
    }

    @Test
    public void testAuthenticateDoesNotCacheInvalidTokenHeader() {
        String invalidToken = base64Json(Map.of("alg", "RS256", "kid", "kid-a")) + ".x";

        JwtHeaderToIssuerMapper mapper = new JwtHeaderToIssuerMapper();
        IssuerAuthenticationManagerResolver resolver = mock(IssuerAuthenticationManagerResolver.class);
        FastReactiveIssuerAuthenticationManager manager = new FastReactiveIssuerAuthenticationManager(resolver, mapper, new DefaultJwtHeaderToIssuerMapperDecider());

        assertThat(manager.authenticate(new BearerTokenAuthenticationToken(invalidToken))
                .onErrorResume(InvalidBearerTokenException.class, e -> Mono.empty())
                .blockOptional()).isEmpty();
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
