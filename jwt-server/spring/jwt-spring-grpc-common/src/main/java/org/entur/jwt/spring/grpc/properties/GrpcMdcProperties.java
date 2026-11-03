package org.entur.jwt.spring.grpc.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "entur.jwt.mdc.grpc")
public class GrpcMdcProperties {

    /**
     * Order of the MDC interceptor. Interceptors with a lower value run first. The JWT is only available to interceptors that run after
     * the authentication interceptor, so by default the MDC interceptor runs right after the Spring gRPC security interceptors.
     */
    private Integer interceptorOrder;

    public Integer getInterceptorOrder() {
        return interceptorOrder;
    }

    public void setInterceptorOrder(Integer interceptorOrder) {
        this.interceptorOrder = interceptorOrder;
    }
}
