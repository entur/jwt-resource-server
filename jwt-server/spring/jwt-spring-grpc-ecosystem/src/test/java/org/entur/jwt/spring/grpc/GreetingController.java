package org.entur.jwt.spring.grpc;


import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import io.grpc.stub.StreamObserver;
import net.devh.boot.grpc.server.security.interceptors.AuthenticatingServerInterceptor;
import net.devh.boot.grpc.server.service.GrpcService;
import org.entur.jwt.spring.grpc.test.GreetingRequest;
import org.entur.jwt.spring.grpc.test.GreetingResponse;
import org.entur.jwt.spring.grpc.test.GreetingServiceGrpc.GreetingServiceImplBase;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import java.util.concurrent.atomic.AtomicLong;

@GrpcService
public class GreetingController extends GreetingServiceImplBase {

    private static Logger log = LoggerFactory.getLogger(GreetingController.class);

    private final AtomicLong counter = new AtomicLong();

    private JwtAuthenticationToken getToken() {
        SecurityContext securityContext = AuthenticatingServerInterceptor.SECURITY_CONTEXT_KEY.get();
        if(securityContext != null) {
            Authentication authentication = securityContext.getAuthentication();

            if(authentication instanceof JwtAuthenticationToken t) {
                return t;
            }
        }
        return null;
    }

    public void unprotected(org.entur.jwt.spring.grpc.test.GreetingRequest request,
                            io.grpc.stub.StreamObserver<org.entur.jwt.spring.grpc.test.GreetingResponse> responseObserver) {
        log.info("Get unprotected method with " + getToken());

        responseObserver.onNext(GreetingResponse.newBuilder().setMessage("Hello unprotected").setStatus(counter.incrementAndGet()).build());
        responseObserver.onCompleted();
    }

    public void unprotectedWithOptionalTenant(org.entur.jwt.spring.grpc.test.GreetingRequest request,
            io.grpc.stub.StreamObserver<org.entur.jwt.spring.grpc.test.GreetingResponse> responseObserver) {

        JwtAuthenticationToken token = getToken();

        if (token != null) {
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

    @Override
    public void protectedOneToOneAuthenticationException(GreetingRequest request, StreamObserver<GreetingResponse> responseObserver) {
        log.info("Get protected one-to-one method which throws AccessDeniedException");

        throw new AccessDeniedException("TEST");
    }
    
    @Override
    public void protectedOneToManyAuthenticationException(GreetingRequest request, StreamObserver<GreetingResponse> responseObserver) {
        log.info("Get protected one-to-many method which throws AccessDeniedException");

        throw new AccessDeniedException("TEST");
    }
    
    @Override
    public StreamObserver<GreetingRequest> protectedManyToOneAuthenticationException(StreamObserver<GreetingResponse> responseObserver) {
        log.info("Get protected many-to-one method which throws AccessDeniedException");

        throw new AccessDeniedException("TEST");
    }
    
    @Override
    public StreamObserver<GreetingRequest> protectedManyToManyAuthenticationException(StreamObserver<GreetingResponse> responseObserver) {
        log.info("Get protected many-to-many method which throws AccessDeniedException");

        throw new AccessDeniedException("TEST");
    }
   
    @Override
    public void protectedOneToOneStatusRuntimeException(GreetingRequest request, StreamObserver<GreetingResponse> responseObserver) {
        log.info("Get protected one-to-one method which throws StatusRuntimeException");

        throw new StatusRuntimeException(Status.UNAUTHENTICATED);
    }
    
    @Override
    public void protectedOneToManyStatusRuntimeException(GreetingRequest request, StreamObserver<GreetingResponse> responseObserver) {
        log.info("Get protected one-to-many method which throws StatusRuntimeException");

        throw new StatusRuntimeException(Status.UNAUTHENTICATED);
    }
    
    @Override
    public StreamObserver<GreetingRequest> protectedManyToOneStatusRuntimeException(StreamObserver<GreetingResponse> responseObserver) {
        log.info("Get protected many-to-one method which throws StatusRuntimeException");

        throw new StatusRuntimeException(Status.UNAUTHENTICATED);
    }
    
    @Override
    public StreamObserver<GreetingRequest> protectedManyToManyStatusRuntimeException(StreamObserver<GreetingResponse> responseObserver) {
        log.info("Get protected many-to-many method which throws StatusRuntimeException");

        throw new StatusRuntimeException(Status.UNAUTHENTICATED);
    }    
}