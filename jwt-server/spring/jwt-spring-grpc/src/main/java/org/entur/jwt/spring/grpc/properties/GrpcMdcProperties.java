package org.entur.jwt.spring.grpc.properties;

import org.entur.jwt.spring.properties.MdcProperties;

public class GrpcMdcProperties extends MdcProperties  {

    private Integer order;

    public Integer getOrder() {
        return order;
    }

    public void setOrder(Integer order) {
        this.order = order;
    }
}
