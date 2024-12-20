package org.entur.jwt.spring.grpc.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;

import java.util.ArrayList;
import java.util.List;

@ConfigurationProperties(prefix = "entur.jwt.exception-handlers")
public class GrpcExceptionHandlers {

    private List<GrpcException> grpc = new ArrayList<>();

    public GrpcExceptionHandlers() {
        // populate default here
        // a little cumbersome but does not restrict the api later

        GrpcException statusAccessDeniedException = new GrpcException();
        statusAccessDeniedException.setName(AccessDeniedException.class.getName());

        GrpcException statusAuthenticationException = new GrpcException();
        statusAuthenticationException.setName(AuthenticationException.class.getName());

        grpc.add(statusAuthenticationException);
        grpc.add(statusAccessDeniedException);
    }

    public List<GrpcException> getGrpc() {
        return grpc;
    }

    public void setGrpc(List<GrpcException> grpc) {
        this.grpc = grpc;
    }

    public GrpcException find(Class c) {
        for(GrpcException e : grpc) {
            if(e.getName().equals(c.getName())) {
                return e;
            }
        }
        return null;
    }
}
