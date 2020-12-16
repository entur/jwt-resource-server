package org.entur.jwt.spring.grpc;

import java.util.concurrent.TimeUnit;

import org.entur.jwt.spring.grpc.test.GreetingRequest;
import org.entur.jwt.spring.grpc.test.GreetingServiceGrpc;
import org.entur.jwt.spring.grpc.test.GreetingServiceGrpc.GreetingServiceBlockingStub;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.lognet.springboot.grpc.context.LocalRunningGrpcPort;
import org.springframework.boot.web.server.LocalServerPort;

import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;

public class AbstractGrpcTest {

    @LocalServerPort
    protected int randomServerPort;

    @LocalRunningGrpcPort
    protected int randomGrpcServerPort;
    
    protected GreetingRequest greetingRequest = GreetingRequest.newBuilder().build();

    protected ManagedChannel managedChannel;

    @BeforeEach
    public void initComm() {
        managedChannel = ManagedChannelBuilder.forAddress("localhost", randomGrpcServerPort).usePlaintext().build();
    }

    @AfterEach
    public void shutdownComm() throws InterruptedException {
        if (managedChannel != null) {
            managedChannel.shutdown();
            managedChannel.awaitTermination(15, TimeUnit.SECONDS);
            managedChannel = null;
        }
    }

    protected GreetingServiceBlockingStub stub() {
        return stub(null);
    }

    protected GreetingServiceBlockingStub stub(String token) {
        GreetingServiceBlockingStub greetingService = GreetingServiceGrpc.newBlockingStub(managedChannel);
        if (token != null) {
            greetingService = greetingService.withCallCredentials(new JwtCallCredentials(token));
        }
        return greetingService;
    }

}
