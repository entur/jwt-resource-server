package org.entur.jwt.spring.grpc.netty;

import io.grpc.ForwardingServerCallListener.SimpleForwardingServerCallListener;
import io.grpc.Metadata;
import io.grpc.ServerCall;
import io.grpc.ServerCall.Listener;
import io.grpc.ServerCallHandler;
import io.grpc.ServerInterceptor;
import org.entur.jwt.spring.filter.log.JwtMappedDiagnosticContextMapper;
import org.entur.jwt.spring.grpc.GrpcMdcAdapter;
import org.springframework.core.Ordered;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import java.util.Map;

/**
 * Copies JWT claims to the MDC via a {@linkplain GrpcMdcAdapter}. The values are available while the call is started and while the call listener is invoked,
 * and are removed afterwards, so thread-local adapters do not leak values between calls.
 * <p>
 * The JWT is read from the security context, so this interceptor must run after the authentication interceptor.
 * Using this interceptor implies there is some kind of MDC context handler.
 */

public class GrpcMdcAuthorizationServerInterceptor implements ServerInterceptor, Ordered {

    private final JwtMappedDiagnosticContextMapper mdcMapper;

    private final int order;

    private final GrpcMdcAdapter mdcAdapter;

    public GrpcMdcAuthorizationServerInterceptor(JwtMappedDiagnosticContextMapper mdcMapper, int order, GrpcMdcAdapter mdcAdapter) {
        this.mdcMapper = mdcMapper;
        this.order = order;
        this.mdcAdapter = mdcAdapter;
    }
    
    @Override
    public <ReqT, RespT> Listener<ReqT> interceptCall(ServerCall<ReqT, RespT> call, Metadata headers, ServerCallHandler<ReqT, RespT> next) {
        Map<String, String> context = getContext();
        if (context.isEmpty()) {
            return next.startCall(call, headers);
        }

        put(context);
        try {
            return new MdcListener<>(next.startCall(call, headers), context);
        } finally {
            remove(context);
        }
    }

    private Map<String, String> getContext() {
        SecurityContext securityContext = SecurityContextHolder.getContext();
        if (securityContext != null) {
            Authentication authentication = securityContext.getAuthentication();

            if (authentication instanceof JwtAuthenticationToken jwtAuthenticationToken) {
                return mdcMapper.getContext(jwtAuthenticationToken.getToken());
            }
        }
        return Map.of();
    }

    private void put(Map<String, String> context) {
        for (Map.Entry<String, String> entry : context.entrySet()) {
            mdcAdapter.put(entry.getKey(), entry.getValue());
        }
    }

    private void remove(Map<String, String> context) {
        for (String key : context.keySet()) {
            mdcAdapter.remove(key);
        }
    }

    @Override
    public int getOrder() {
        return order;
    }

    /** Listener callbacks might be invoked on a different thread than the one which started the call. */
    private class MdcListener<ReqT> extends SimpleForwardingServerCallListener<ReqT> {

        private final Map<String, String> context;

        MdcListener(Listener<ReqT> delegate, Map<String, String> context) {
            super(delegate);
            this.context = context;
        }

        @Override
        public void onMessage(ReqT message) {
            withContext(() -> super.onMessage(message));
        }

        @Override
        public void onHalfClose() {
            withContext(super::onHalfClose);
        }

        @Override
        public void onCancel() {
            withContext(super::onCancel);
        }

        @Override
        public void onComplete() {
            withContext(super::onComplete);
        }

        @Override
        public void onReady() {
            withContext(super::onReady);
        }

        private void withContext(Runnable callback) {
            put(context);
            try {
                callback.run();
            } finally {
                remove(context);
            }
        }
    }
}
