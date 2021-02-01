package org.entur.jwt.spring.grpc;


import java.util.Objects;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.util.ThrowableAnalyzer;

import io.grpc.ForwardingServerCallListener.SimpleForwardingServerCallListener;
import io.grpc.ServerCall.Listener;
import io.grpc.Metadata;
import io.grpc.ServerCall;
import io.grpc.ServerCallHandler;
import io.grpc.ServerInterceptor;
import io.grpc.Status;

public class AuthenticationExceptionTranslationInterceptor implements ServerInterceptor {

    private static Logger log = LoggerFactory.getLogger(AuthenticationExceptionTranslationInterceptor.class);

    private ThrowableAnalyzer throwableAnalyzer = new ThrowableAnalyzer();

    @Override
    public <ReqT, RespT> ServerCall.Listener<ReqT> interceptCall(
            ServerCall<ReqT, RespT> call,
            Metadata headers,
            ServerCallHandler<ReqT, RespT> next) {
        try {
            ServerCall.Listener<ReqT> delegate = next.startCall(call, headers);
            return new SimpleForwardingServerCallListener<ReqT>(delegate) {

                @Override
                public void onHalfClose() {
                    try {
                        super.onHalfClose();
                    } catch (RuntimeException e) {
                        translateToStatus(e, call);
                    }
                }
            };

        } catch(RuntimeException e) {
            Throwable[] causeChain = throwableAnalyzer.determineCauseChain(e);
            AuthenticationException authenticationException = (AuthenticationException) throwableAnalyzer.getFirstThrowableOfType(AuthenticationException.class, causeChain);

            if (Objects.nonNull(authenticationException)) {
                log.warn("Got authentication exception", e);

                call.close(Status.UNAUTHENTICATED, new Metadata());
                return new Listener<ReqT>() {};
            } else {
                AccessDeniedException accessDeniedException = (AccessDeniedException) throwableAnalyzer.getFirstThrowableOfType(AccessDeniedException.class, causeChain);
                if (Objects.nonNull(accessDeniedException)) {
                    log.warn("Got permission denied exception", e);
                    call.close(Status.PERMISSION_DENIED, new Metadata());
                    
                    return new Listener<ReqT>() {};
                } else {
                    throw e;
                }
            }
        }
    }

    private <ReqT, RespT> void translateToStatus(RuntimeException e, ServerCall<ReqT, RespT> call) {
        Throwable[] causeChain = throwableAnalyzer.determineCauseChain(e);
        AuthenticationException authenticationException = (AuthenticationException) throwableAnalyzer.getFirstThrowableOfType(AuthenticationException.class, causeChain);

        if (Objects.nonNull(authenticationException)) {
            log.warn("Got authentication exception", e);
            handleAuthenticationException(authenticationException, call);
        } else {
            AccessDeniedException accessDeniedException = (AccessDeniedException) throwableAnalyzer.getFirstThrowableOfType(AccessDeniedException.class, causeChain);
            if (Objects.nonNull(accessDeniedException)) {
                log.warn("Got permission denied exception", e);
                handleAccessDeniedException(accessDeniedException, call);
            } else {
                throw e;
            }
        }
    }
    
    private static <ReqT, RespT> void handleAuthenticationException(AuthenticationException exception, ServerCall<ReqT, RespT> call) {
        call.close(Status.UNAUTHENTICATED, new Metadata());
    }

    private static <ReqT, RespT> void handleAccessDeniedException(AccessDeniedException exception, ServerCall<ReqT, RespT> call) {
        call.close(Status.PERMISSION_DENIED, new Metadata());
    }

}