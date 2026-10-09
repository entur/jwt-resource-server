package org.entur.jwt.spring.demo;

import org.entur.jwt.junit5.AccessToken;
import org.entur.jwt.junit5.AuthorizationServer;
import org.entur.jwt.spring.decode.ClosableJwtDecoders;
import org.entur.jwt.spring.demo.grpc.GreetingRequest;
import org.entur.jwt.spring.grpc.netty.GrpcJwtDecoderHolder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.ApplicationContext;
import org.springframework.http.HttpStatus;
import org.springframework.test.annotation.DirtiesContext;

import static io.restassured.RestAssured.given;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * With both REST (jwt-spring-web) and gRPC (jwt-spring-grpc-native), the JWT decoders are shared,
 * i.e. there is one set of decoders, not one per module.
 */
@AuthorizationServer("a")
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@DirtiesContext
public class SharedJwtDecodersTest {

    private static final String ISSUER = "https://mock.issuer.a.xyz";

    @LocalServerPort
    private int port;

    @Autowired
    private ApplicationContext context;

    @Autowired
    private ClosableJwtDecoders closableJwtDecoders;

    @Autowired
    private GrpcJwtDecoderHolder grpcJwtDecoderHolder;

    private final GrpcClient client = new GrpcClient();

    @AfterEach
    public void close() throws InterruptedException {
        client.close();
    }

    @Test
    public void testDecodersAreShared() {
        assertThat(context.getBeansOfType(ClosableJwtDecoders.class)).hasSize(1);

        // single tenant, so the gRPC decoder is the tenant decoder itself
        assertThat(grpcJwtDecoderHolder.getJwtDecoder()).isSameAs(closableJwtDecoders.getJwtDecoders().get(ISSUER));
    }

    @Test
    public void testSameTokenAcceptedForRestAndGrpc(@AccessToken(by = "a", audience = "https://my.audience") String token) {
        given().port(port).when().header("Authorization", token).get("/protected").then().assertThat().statusCode(HttpStatus.OK.value());

        assertThat(client.stub(token).protectedGreeting(GreetingRequest.getDefaultInstance())).isNotNull();
    }
}
