package org.entur.jwt.spring.demo;

import io.grpc.CallCredentials;
import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;
import io.grpc.Metadata;
import org.entur.jwt.spring.demo.grpc.GreetingServiceGrpc;

import java.util.concurrent.Executor;
import java.util.concurrent.TimeUnit;

/**
 * gRPC client for the tests, optionally sending a bearer token.
 */
public class GrpcClient implements AutoCloseable {

    // default gRPC server port
    private static final int PORT = 9090;

    private final ManagedChannel channel = ManagedChannelBuilder.forAddress("localhost", PORT).usePlaintext().build();

    public GreetingServiceGrpc.GreetingServiceBlockingStub stub() {
        return GreetingServiceGrpc.newBlockingStub(channel);
    }

    public GreetingServiceGrpc.GreetingServiceBlockingStub stub(String token) {
        return stub().withCallCredentials(new BearerTokenCredentials(token));
    }

    @Override
    public void close() throws InterruptedException {
        channel.shutdown();
        channel.awaitTermination(15, TimeUnit.SECONDS);
    }

    private static class BearerTokenCredentials extends CallCredentials {

        private static final Metadata.Key<String> AUTHORIZATION = Metadata.Key.of("Authorization", Metadata.ASCII_STRING_MARSHALLER);

        private final String token;

        BearerTokenCredentials(String token) {
            this.token = token;
        }

        @Override
        public void applyRequestMetadata(RequestInfo requestInfo, Executor executor, MetadataApplier metadataApplier) {
            executor.execute(() -> {
                Metadata headers = new Metadata();
                headers.put(AUTHORIZATION, token);
                metadataApplier.apply(headers);
            });
        }
    }
}
