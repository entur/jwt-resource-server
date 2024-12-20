package org.entur.jwt.spring.grpc.lognet;

import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;
import org.entur.jwt.spring.grpc.test.GreetingRequest;
import org.entur.jwt.spring.grpc.test.GreetingServiceGrpc;
import org.entur.jwt.spring.grpc.test.GreetingServiceGrpc.GreetingServiceBlockingStub;
import org.entur.jwt.spring.grpc.test.GreetingServiceGrpc.GreetingServiceFutureStub;
import org.entur.jwt.spring.grpc.test.GreetingServiceGrpc.GreetingServiceStub;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.lognet.springboot.grpc.context.LocalRunningGrpcPort;
import org.springframework.boot.test.web.server.LocalServerPort;

import java.util.concurrent.TimeUnit;

public class AbstractGrpcTest {

    public static final int MAX_INBOUND_MESSAGE_SIZE = 1 << 20;
    public static final int MAX_OUTBOUND_MESSAGE_SIZE = 1 << 20;

    protected final int maxOutboundMessageSize;
    protected final int maxInboundMessageSize;

    public AbstractGrpcTest() {
        this(MAX_INBOUND_MESSAGE_SIZE, MAX_OUTBOUND_MESSAGE_SIZE);
    }

    public AbstractGrpcTest(int maxInboundMessageSize, int maxOutboundMessageSize) {
        this.maxInboundMessageSize = maxInboundMessageSize;
        this.maxOutboundMessageSize = maxOutboundMessageSize;
    }

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

    protected void shutdown(GreetingServiceBlockingStub stub) throws InterruptedException {
        ManagedChannel m = (ManagedChannel)stub.getChannel();
        m.shutdown();
        m.awaitTermination(15, TimeUnit.SECONDS);
    }

    protected GreetingServiceFutureStub futureStub(String token) {
        GreetingServiceFutureStub newFutureStub = GreetingServiceGrpc.newFutureStub(managedChannel);
        if (token != null) {
            newFutureStub = newFutureStub.withCallCredentials(new JwtCallCredentials(token));
        }
        return newFutureStub;
    }    

    protected GreetingServiceBlockingStub stub(String token) {
        GreetingServiceBlockingStub greetingService = GreetingServiceGrpc.newBlockingStub(managedChannel);
        if (token != null) {
            greetingService = greetingService.withCallCredentials(new JwtCallCredentials(token));
        }
        return greetingService;
    }

    protected GreetingServiceStub async(String token) {
        GreetingServiceStub greetingService = GreetingServiceGrpc.newStub(managedChannel)
                .withMaxInboundMessageSize(maxInboundMessageSize)
                .withMaxOutboundMessageSize(maxOutboundMessageSize)
                ;
        if (token != null) {
            greetingService = greetingService.withCallCredentials(new JwtCallCredentials(token));
        }

        return greetingService;
    }

}
