package org.entur.jwt.spring.grpc.ecosystem;

import io.grpc.Context;
import io.grpc.Contexts;
import io.grpc.Metadata;
import io.grpc.ServerCall;
import io.grpc.ServerCall.Listener;
import io.grpc.ServerCallHandler;
import io.grpc.ServerInterceptor;
import net.devh.boot.grpc.server.security.interceptors.AuthenticatingServerInterceptor;
import org.entur.jwt.spring.filter.log.JwtMappedDiagnosticContextMapper;
import org.entur.jwt.spring.grpc.GrpcMdcAdapter;
import org.springframework.core.Ordered;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import net.devh.boot.grpc.server.advice.GrpcAdvice;
import net.devh.boot.grpc.server.advice.GrpcExceptionHandler;
import java.util.Map;

/**
 * Using this interceptor implies there is some kind of MDC context handler
 *
 */

public class GrpcEcosystemMdcAuthorizationServerInterceptor implements ServerInterceptor, Ordered {

    private final JwtMappedDiagnosticContextMapper mdcMapper;

    private final int order;

    private final GrpcMdcAdapter mdcAdapter;

    public GrpcEcosystemMdcAuthorizationServerInterceptor(JwtMappedDiagnosticContextMapper mdcMapper, int order, GrpcMdcAdapter mdcAdapter) {
        this.mdcMapper = mdcMapper;
        this.order = order;
        this.mdcAdapter = mdcAdapter;
    }
    
    @Override
    public <ReqT, RespT> Listener<ReqT> interceptCall(ServerCall<ReqT, RespT> call, Metadata headers, ServerCallHandler<ReqT, RespT> next) {
        SecurityContext securityContext = AuthenticatingServerInterceptor.SECURITY_CONTEXT_KEY.get();
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