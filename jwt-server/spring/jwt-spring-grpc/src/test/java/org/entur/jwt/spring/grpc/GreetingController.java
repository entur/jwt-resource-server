package org.entur.jwt.spring.grpc;


import java.util.concurrent.atomic.AtomicLong;

import org.entur.jwt.spring.filter.JwtAuthenticationToken;
import org.entur.jwt.spring.grpc.test.GreetingResponse;
import org.entur.jwt.spring.grpc.test.GreetingServiceGrpc.GreetingServiceImplBase;
import org.lognet.springboot.grpc.GRpcService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@GRpcService
public class GreetingController extends GreetingServiceImplBase implements GrpcAuthorization {

    private static Logger log = LoggerFactory.getLogger(GreetingController.class);

    private final AtomicLong counter = new AtomicLong();
    
    public void unprotected(org.entur.jwt.spring.grpc.test.GreetingRequest request,
            io.grpc.stub.StreamObserver<org.entur.jwt.spring.grpc.test.GreetingResponse> responseObserver) {
        log.info("Get unprotected method");
        
        responseObserver.onNext(GreetingResponse.newBuilder().setMessage("Hello unprotected").setStatus(counter.incrementAndGet()).build());
        responseObserver.onCompleted();
    }

    public void unprotectedWithOptionalTenant(org.entur.jwt.spring.grpc.test.GreetingRequest request,
            io.grpc.stub.StreamObserver<org.entur.jwt.spring.grpc.test.GreetingResponse> responseObserver) {

        JwtAuthenticationToken token = getToken();
        
        if(token != null) {
            log.info("Get unprotected method with tenant present " + token);
            responseObserver.onNext(GreetingResponse.newBuilder().setMessage("Hello unprotected method with tenant present " + token).setStatus(counter.incrementAndGet()).build());
        } else {
            log.info("Get unprotected method with tenant not present");
            responseObserver.onNext(GreetingResponse.newBuilder().setMessage("Hello unprotected method with tenant not present").setStatus(counter.incrementAndGet()).build());
        }
        
        responseObserver.onCompleted();
    }
    
    public void protectedWithPartnerTenant(org.entur.jwt.spring.grpc.test.GreetingRequest request,
            io.grpc.stub.StreamObserver<org.entur.jwt.spring.grpc.test.GreetingResponse> responseObserver) {
        
        JwtAuthenticationToken token = getToken();
        log.info("Tenant {}", token);

        responseObserver.onNext(GreetingResponse.newBuilder().setMessage("Hello protected tenant").setStatus(counter.incrementAndGet()).build());
        responseObserver.onCompleted();
    }

}