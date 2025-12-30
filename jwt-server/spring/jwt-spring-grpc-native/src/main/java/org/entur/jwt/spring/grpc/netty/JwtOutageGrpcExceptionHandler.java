package org.entur.jwt.spring.grpc.netty;

import com.nimbusds.jose.KeySourceException;
import io.grpc.Status;
import io.grpc.StatusException;
import org.jspecify.annotations.Nullable;
import org.springframework.core.Ordered;
import org.springframework.grpc.server.exception.GrpcExceptionHandler;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.jwt.JwtException;

public class JwtOutageGrpcExceptionHandler implements GrpcExceptionHandler, Ordered {

    private final int order;

    public JwtOutageGrpcExceptionHandler(int order) {
        this.order = order;
    }

    @Override
	public @Nullable StatusException handleException(Throwable e) {
		if (e instanceof AuthenticationException) {
            if (e instanceof AuthenticationServiceException) {
                Throwable cause1 = e.getCause();
                if (cause1 instanceof JwtException) {
                    Throwable cause2 = cause1.getCause();
                    if (cause2 instanceof KeySourceException) {
                        return Status.UNAVAILABLE.withDescription(e.getMessage()).asException();
                    }
                }
            }
        }
		return null;
	}

    @Override
    public int getOrder() {
        return order;
    }
}
