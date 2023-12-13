package org.entur.jwt.spring.grpc.properties;

import org.entur.jwt.spring.properties.MdcProperties;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "entur.jwt.mdc.grpc")
public class GrpcMdcProperties {

    private Integer order;

    public Integer getOrder() {
        return order;
    }

    public void setOrder(Integer order) {
        this.order = order;
    }
}
