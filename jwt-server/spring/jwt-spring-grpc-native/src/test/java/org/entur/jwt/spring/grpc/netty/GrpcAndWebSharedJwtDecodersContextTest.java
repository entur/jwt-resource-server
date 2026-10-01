package org.entur.jwt.spring.grpc.netty;

import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.entur.jwt.junit5.AccessToken;
import org.entur.jwt.junit5.AuthorizationServer;
import org.entur.jwt.spring.JwkSourceMap;
import org.entur.jwt.spring.actuate.ListEventListener;
import org.entur.jwt.spring.decode.ClosableJwtDecoders;
import org.entur.jwt.spring.decode.IssuerJwtDecoder;
import org.entur.jwt.spring.decode.cache.DecodedJwtCacheJwkEventListener;
import org.entur.jwt.spring.decode.cache.DecodedJwtCacheJwtDecoder;
import org.entur.jwt.spring.grpc.AbstractGrpcTest;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.TestPropertySource;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * With both the web and the gRPC module, the per-issuer JWT decoders (and so the decoded JWT caches) are shared.
 */
@AuthorizationServer("a")
@AuthorizationServer("b")
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@TestPropertySource(properties = {
        // include the web module, which is excluded by default for the gRPC tests
        "spring.autoconfigure.exclude=",
        "entur.jwt.tenants.a.decoder-cache.enabled=true",
        "entur.jwt.jwk.cache.preemptive.eager.enabled=true",
})
@DirtiesContext
public class GrpcAndWebSharedJwtDecodersContextTest extends AbstractGrpcTest {

    private static final String ISSUER_A = "https://mock.issuer.a.xyz";

    @Autowired
    private ApplicationContext context;

    @Autowired
    private GrpcJwtDecoderHolder grpcJwtDecoderHolder;

    @Autowired
    private ClosableJwtDecoders closableJwtDecoders;

    @Autowired
    private JwkSourceMap jwkSourceMap;

    @Test
    public void testWebModuleIsActive() {
        assertThat(context.getBeansOfType(SecurityFilterChain.class)).isNotEmpty();
    }

    @Test
    public void testSingleSharedDecoders() {
        assertThat(context.getBeansOfType(ClosableJwtDecoders.class)).hasSize(1);

        JwtDecoder decoder = grpcJwtDecoderHolder.getJwtDecoder();
        assertThat(decoder).isInstanceOf(IssuerJwtDecoder.class);

        JwtDecoder a = ((IssuerJwtDecoder) decoder).getJwtDecoders().get(ISSUER_A);
        assertThat(a).isInstanceOf(DecodedJwtCacheJwtDecoder.class);
        assertThat(a).isSameAs(closableJwtDecoders.getJwtDecoders().get(ISSUER_A));
    }

    @Test
    public void testSingleCacheListenerPerTenant() {
        @SuppressWarnings("unchecked")
        Map<String, ListEventListener> listenersByIssuer = jwkSourceMap.getJwkEventListeners();
        long listeners = listenersByIssuer.get(ISSUER_A).getEventListeners().stream()
                .filter(DecodedJwtCacheJwkEventListener.class::isInstance)
                .count();
        assertThat(listeners).isEqualTo(1);
    }

    @Test
    public void testGrpcRequestPopulatesSharedCache(@AccessToken(by = "a", audience = "https://my.audience") String token) throws Exception {
        // load the JWK set first, a JWT is not cached if the JWK set is (re)loaded while decoding it
        @SuppressWarnings("unchecked")
        JWKSource<SecurityContext> jwkSource = (JWKSource<SecurityContext>) jwkSourceMap.getJwkSources().get(ISSUER_A);
        jwkSource.get(new JWKSelector(new JWKMatcher.Builder().build()), null);

        DecodedJwtCacheJwtDecoder a = (DecodedJwtCacheJwtDecoder) closableJwtDecoders.getJwtDecoders().get(ISSUER_A);
        a.clear();

        stub(token).protectedWithPartnerTenant(greetingRequest);

        assertThat(a.getSize()).isEqualTo(1);
    }
}
