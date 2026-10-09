package org.entur.jwt.spring.demo;

import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.entur.jwt.junit5.AccessToken;
import org.entur.jwt.junit5.AuthorizationServer;
import org.entur.jwt.spring.JwkSourceMap;
import org.entur.jwt.spring.decode.ClosableJwtDecoders;
import org.entur.jwt.spring.decode.cache.DecodedJwtCacheJwtDecoder;
import org.entur.jwt.spring.demo.grpc.GreetingRequest;
import org.entur.jwt.spring.grpc.netty.GrpcJwtDecoderHolder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.ApplicationContext;
import org.springframework.http.HttpStatus;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.TestPropertySource;

import static io.restassured.RestAssured.given;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * With both REST (jwt-spring-web) and gRPC (jwt-spring-grpc-native), the JWT decoders, and so the
 * decoded JWT cache, are shared: a token used for both REST and gRPC is decoded (and its signature verified) once.
 */
@AuthorizationServer("a")
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@DirtiesContext
@TestPropertySource(properties = {
        "entur.jwt.tenants.a.decoder-cache.enabled=true",
})
public class SharedJwtDecoderCacheTest {

    private static final String ISSUER = "https://mock.issuer.a.xyz";

    @LocalServerPort
    private int port;

    @Autowired
    private ApplicationContext context;

    @Autowired
    private ClosableJwtDecoders closableJwtDecoders;

    @Autowired
    private GrpcJwtDecoderHolder grpcJwtDecoderHolder;

    @Autowired
    private JwkSourceMap jwkSourceMap;

    private final GrpcClient client = new GrpcClient();

    private DecodedJwtCacheJwtDecoder cache;

    @BeforeEach
    @SuppressWarnings("unchecked")
    public void loadJwks() throws Exception {
        // a JWT is not cached if the JWK set is (re)loaded while decoding it, so load the JWK set up front
        JWKSource<SecurityContext> jwkSource = (JWKSource<SecurityContext>) jwkSourceMap.getJwkSources().get(ISSUER);
        jwkSource.get(new JWKSelector(new JWKMatcher.Builder().build()), null);

        cache = (DecodedJwtCacheJwtDecoder) closableJwtDecoders.getJwtDecoders().get(ISSUER);
        cache.clear();
    }

    @AfterEach
    public void close() throws InterruptedException {
        client.close();
    }

    @Test
    public void testDecodersAreShared() {
        assertThat(context.getBeansOfType(ClosableJwtDecoders.class)).hasSize(1);

        // single tenant, so the gRPC decoder is the tenant decoder itself
        assertThat(grpcJwtDecoderHolder.getJwtDecoder()).isSameAs(cache);
    }

    @Test
    public void testTokenIsCachedOnceForRestAndGrpc(@AccessToken(by = "a", audience = "https://my.audience") String token) {
        given().port(port).when().header("Authorization", token).get("/protected").then().assertThat().statusCode(HttpStatus.OK.value());
        assertThat(cache.getSize()).isEqualTo(1);

        client.stub(token).protectedGreeting(GreetingRequest.getDefaultInstance());
        assertThat(cache.getSize()).isEqualTo(1);
    }
}
