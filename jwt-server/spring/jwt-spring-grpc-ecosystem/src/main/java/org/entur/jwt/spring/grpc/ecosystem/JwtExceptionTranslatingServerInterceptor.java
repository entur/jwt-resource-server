package org.entur.jwt.spring.grpc.ecosystem;

import com.nimbusds.jose.KeySourceException;
import io.grpc.ForwardingServerCallListener;
import io.grpc.Metadata;
import io.grpc.ServerCall;
import io.grpc.ServerCallHandler;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import net.devh.boot.grpc.common.util.InterceptorOrder;
import net.devh.boot.grpc.server.interceptor.GrpcGlobalServerInterceptor;
import net.devh.boot.grpc.server.security.interceptors.ExceptionTranslatingServerInterceptor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.jwt.JwtException;

/**
 * More strict version of the {@linkplain ExceptionTranslatingServerInterceptor}.
 *
 * Handles service unavailable for {@linkplain AuthenticationException} causes by JWK outage.
 * Handles status runtime exceptions if unauthenticated / permission denied on half close.
 * Returns status with a message (not a cause).
 *
 *
 */

public class JwtExceptionTranslatingServerInterceptor extends ExceptionTranslatingServerInterceptor implements Ordered {

    private static Logger log = LoggerFactory.getLogger(JwtExceptionTranslatingServerInterceptor.class);

    protected final int order;

    public JwtExceptionTranslatingServerInterceptor(int order) {
        this.order = order;
    }

    @Override
    public <ReqT, RespT> ServerCall.Listener<ReqT> interceptCall(final ServerCall<ReqT, RespT> call,
                                                                 final Metadata headers,
                                                                 final ServerCallHandler<ReqT, RespT> next) {
        try {
            // Streaming calls error out here
            return new ExtendedExceptionTranslatorServerCallListener<>(next.startCall(call, headers), call);
        } catch (final AuthenticationException aex) {
            closeCallUnauthenticated(call, aex);
            return noOpCallListener();
        } catch (final AccessDeniedException aex) {
            closeCallAccessDenied(call, aex);
            return noOpCallListener();
        }
    }

    /**
     * Close the call with {@link Status#UNAUTHENTICATED} or {@link Status#UNAVAILABLE}
     *
     * @param call The call to close.
     * @param e The exception that was the cause.
     */

    @Override
    protected void closeCallUnauthenticated(final ServerCall<?, ?> call, final AuthenticationException e) {
        if (e instanceof AuthenticationServiceException) {
            Throwable cause1 = e.getCause();
            if (cause1 instanceof JwtException) {
                Throwable cause2 = cause1.getCause();
                if (cause2 instanceof KeySourceException) {
                    call.close(Status.UNAVAILABLE.withDescription(e.getMessage()), new Metadata());
                    return;
                }
            }
        }
        call.close(Status.UNAUTHENTICATED.withDescription(e.getMessage()), new Metadata());
    }

    /**
     * Close the call with {@link Status#PERMISSION_DENIED}.
     *
     * @param call The call to close.
     * @param e The exception that was the cause.
     */
    @Override
    protected void closeCallAccessDenied(final ServerCall<?, ?> call, final AccessDeniedException e) {
        call.close(Status.PERMISSION_DENIED.withDescription(e.getMessage()), new Metadata());
    }

    @Override
    public int getOrder() {
        return order;
    }

    /**
     * Server call listener that catches and handles exceptions in {@link #onHalfClose()}.
     *
     * @param <ReqT> The type of the request.
     * @param <RespT> The type of the response.
     */
    private class ExtendedExceptionTranslatorServerCallListener<ReqT, RespT> extends ForwardingServerCallListener.SimpleForwardingServerCallListener<ReqT> {

        private final ServerCall<ReqT, RespT> call;

        protected ExtendedExceptionTranslatorServerCallListener(final ServerCall.Listener<ReqT> delegate,
                                                        final ServerCall<ReqT, RespT> call) {
            super(delegate);
            this.call = call;
        }

        @Override
        // Unary calls error out here
        public void onHalfClose() {
            try {
                super.onHalfClose();
            } catch (final AuthenticationException aex) {
                closeCallUnauthenticated(this.call, aex);
            } catch (final AccessDeniedException aex) {
                closeCallAccessDenied(this.call, aex);
            } catch(final StatusRuntimeException e) {
                // handle security-related statuses here
                Status status = e.getStatus();
                if(status.getCode() == Status.Code.UNAUTHENTICATED) {
                    closeCallUnauthenticated(this.call, e);
                } else if(status.getCode() == Status.Code.PERMISSION_DENIED) {
                    closeCallAccessDenied(this.call, e);
                } else {
                    throw e;
                }
            }
        }

    }
    /**
     * Close the call with {@link Status#UNAUTHENTICATED}.
     *
     * @param call The call to close.
     * @param e The exception that was the cause.
     */

    protected void closeCallUnauthenticated(final ServerCall<?, ?> call, final StatusRuntimeException e) {
        call.close(Status.UNAUTHENTICATED.withDescription(e.getMessage()), new Metadata());
    }

    /**
     * Close the call with {@link Status#PERMISSION_DENIED}.
     *
     * @param call The call to close.
     * @param e The exception that was the cause.
     */
    protected void closeCallAccessDenied(final ServerCall<?, ?> call, final StatusRuntimeException e) {
        call.close(Status.PERMISSION_DENIED.withDescription(e.getMessage()), new Metadata());
    }

}
