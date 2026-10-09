package org.entur.jwt.spring.demo;

import io.grpc.stub.StreamObserver;
import org.entur.jwt.spring.demo.grpc.GreetingRequest;
import org.entur.jwt.spring.demo.grpc.GreetingResponse;
import org.entur.jwt.spring.demo.grpc.GreetingServiceGrpc;
import org.springframework.grpc.server.service.GrpcService;

import java.util.concurrent.atomic.AtomicLong;

/**
 * gRPC service, secured by the jwt-spring-grpc-native module. The unprotected method is listed under
 * {@code entur.authorization.permit-all.grpc} in the application configuration; all other methods require a valid token.
 */
@GrpcService
public class GreetingGrpcService extends GreetingServiceGrpc.GreetingServiceImplBase {

    private final AtomicLong counter = new AtomicLong();

    @Override
    public void unprotected(GreetingRequest request, StreamObserver<GreetingResponse> responseObserver) {
        respond(responseObserver, "Hello unprotected");
    }

    @Override
    public void protectedGreeting(GreetingRequest request, StreamObserver<GreetingResponse> responseObserver) {
        respond(responseObserver, "Hello protected");
    }

    private void respond(StreamObserver<GreetingResponse> responseObserver, String message) {
        responseObserver.onNext(GreetingResponse.newBuilder().setId(counter.incrementAndGet()).setMessage(message).build());
        responseObserver.onCompleted();
    }
}
