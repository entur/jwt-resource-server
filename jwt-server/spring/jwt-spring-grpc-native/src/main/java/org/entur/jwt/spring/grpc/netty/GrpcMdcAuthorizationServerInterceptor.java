package org.entur.jwt.spring.grpc.netty;

import io.grpc.Context;
import io.grpc.Contexts;
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
 * Using this interceptor implies there is some kind of MDC context handler
 *
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
        SecurityContext securityContext = SecurityContextHolder.getContext();
        if(securityContext != null) {
            Authentication authentication = securityContext.getAuthentication();

            if (authentication instanceof JwtAuthenticationToken jwtAuthenticationToken) {
                Map<String, String> context = mdcMapper.getContext(jwtAuthenticationToken.getToken());

                for (Map.Entry<String, String> entry : context.entrySet()) {
                    mdcAdapter.put(entry.getKey(), entry.getValue());
                }
            }
        }
        return Contexts.interceptCall(Context.current(), call, headers, next);
    }

    @Override
    public int getOrder() {
        return order;
    }
}