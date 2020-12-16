package org.entur.jwt.spring.grpc;


import java.util.Objects;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.util.ThrowableAnalyzer;

import io.grpc.ForwardingServerCallListener.SimpleForwardingServerCallListener;
import io.grpc.Metadata;
import io.grpc.ServerCall;
import io.grpc.ServerCallHandler;
import io.grpc.ServerInterceptor;
import io.grpc.Status;


public class AuthenticationExceptionTranslationInterceptor implements ServerInterceptor {

    private ThrowableAnalyzer throwableAnalyzer = new ThrowableAnalyzer();

    @Override
    public <ReqT, RespT> ServerCall.Listener<ReqT> interceptCall(
            ServerCall<ReqT, RespT> call,
            Metadata headers,
            ServerCallHandler<ReqT, RespT> next) {
        ServerCall.Listener<ReqT> delegate = next.startCall(call, headers);
        return new SimpleForwardingServerCallListener<ReqT>(delegate) {
            @Override
            public void onHalfClose() {
                try {
                    super.onHalfClose();
                } catch (Exception e) {
                    Throwable[] causeChain = throwableAnalyzer.determineCauseChain(e);
                    AuthenticationException authenticationException = (AuthenticationException) throwableAnalyzer.getFirstThrowableOfType(AuthenticationException.class, causeChain);

                    if (Objects.nonNull(authenticationException)) {
                        handleAuthenticationException(authenticationException);
                    } else {
                        AccessDeniedException accessDeniedException = (AccessDeniedException) throwableAnalyzer.getFirstThrowableOfType(AccessDeniedException.class, causeChain);

                        if (Objects.nonNull(accessDeniedException)) {
                            handleAccessDeniedException(accessDeniedException);
                        } else {
                            throw e;
                        }
                    }
                }
            }

            private void handleAuthenticationException(AuthenticationException exception) {
                call.close(Status.UNAUTHENTICATED.withDescription(exception.getMessage())
                        .withCause(exception), new Metadata());
            }

            private void handleAccessDeniedException(AccessDeniedException exception) {
                call.close(Status.PERMISSION_DENIED.withDescription(exception.getMessage())
                        .withCause(exception), new Metadata());
            }
        };
    }
}