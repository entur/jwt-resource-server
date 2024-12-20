package org.entur.jwt.spring.grpc;

import io.grpc.health.v1.HealthCheckRequest;
import io.grpc.health.v1.HealthCheckResponse;
import io.grpc.health.v1.HealthGrpc;
import org.entur.jwt.junit5.AuthorizationServer;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.annotation.DirtiesContext;

import static org.junit.jupiter.api.Assertions.assertEquals;

@AuthorizationServer
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@DirtiesContext
public class HealthCheckTest extends AbstractGrpcTest {

	@Test
	public void testGrpcHealth() throws Exception {
		final HealthCheckRequest healthCheckRequest = HealthCheckRequest.newBuilder().build();
		final HealthGrpc.HealthFutureStub healthFutureStub = HealthGrpc.newFutureStub(managedChannel);
		final HealthCheckResponse.ServingStatus servingStatus = healthFutureStub.check(healthCheckRequest).get().getStatus();

		assertEquals(servingStatus, HealthCheckResponse.ServingStatus.SERVING);
	}
}
