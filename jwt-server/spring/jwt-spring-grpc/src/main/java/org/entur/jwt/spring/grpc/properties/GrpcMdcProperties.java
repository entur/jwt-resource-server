package org.entur.jwt.spring.grpc.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "entur.jwt.mdc.grpc")
public class GrpcMdcProperties {

    private Integer interceptorOrder;

    public Integer getInterceptorOrder() {
        return interceptorOrder;
    }

    public void setInterceptorOrder(Integer interceptorOrder) {
        this.interceptorOrder = interceptorOrder;
    }
}
