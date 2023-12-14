package org.entur.jwt.spring.grpc.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "entur.jwt.mdc.grpc")
public class GrpcMdcProperties {

    private int interceptorOrder;

    public int getInterceptorOrder() {
        return interceptorOrder;
    }

    public void setInterceptorOrder(int interceptorOrder) {
        this.interceptorOrder = interceptorOrder;
    }
}
