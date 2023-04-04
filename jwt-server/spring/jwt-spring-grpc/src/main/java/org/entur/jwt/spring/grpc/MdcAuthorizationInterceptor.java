package org.entur.jwt.spring.grpc;

import io.grpc.Context;
import io.grpc.Contexts;
import io.grpc.Metadata;
import io.grpc.ServerCall;
import io.grpc.ServerCall.Listener;
import io.grpc.ServerCallHandler;
import io.grpc.ServerInterceptor;
import org.entur.jwt.spring.filter.log.JwtMappedDiagnosticContextMapper;
import org.lognet.springboot.grpc.security.GrpcSecurity;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.Ordered;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

public class MdcAuthorizationInterceptor<T> implements ServerInterceptor, Ordered {

    private static final Logger log = LoggerFactory.getLogger(MdcAuthorizationInterceptor.class);

    private final JwtMappedDiagnosticContextMapper mdcMapper;

    private final int order;

    public MdcAuthorizationInterceptor(JwtMappedDiagnosticContextMapper mdcMapper, int order) {
        this.mdcMapper = mdcMapper;
        this.order = order;
    }
    
    @Override
    public <ReqT, RespT> Listener<ReqT> interceptCall(ServerCall<ReqT, RespT> call, Metadata headers, ServerCallHandler<ReqT, RespT> next) {
        Authentication authentication = GrpcSecurity.AUTHENTICATION_CONTEXT_KEY.get();

        Context context = Context.current();
        if (authentication instanceof JwtAuthenticationToken) {
            JwtAuthenticationToken jwtAuthenticationToken = (JwtAuthenticationToken)authentication;
            context = context.withValue(GrpcAuthorization.SECURITY_CONTEXT_MDC, mdcMapper.getContext(jwtAuthenticationToken.getToken()));
        }

        return Contexts.interceptCall(context, call, headers, next);
    }

    @Override
    public int getOrder() {
        return order;
    }
}