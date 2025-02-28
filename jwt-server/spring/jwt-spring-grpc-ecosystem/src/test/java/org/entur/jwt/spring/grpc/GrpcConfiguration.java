package org.entur.jwt.spring.grpc;

import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import net.devh.boot.grpc.server.advice.GrpcAdvice;
import net.devh.boot.grpc.server.advice.GrpcExceptionHandler;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Configuration;

@Configuration
public class GrpcConfiguration {

    // add advice so that the error handler interceptor is also added

    @GrpcAdvice
    public static class StatusRuntimeExceptionGrpcServiceAdvice {
        @java.lang.SuppressWarnings("all")

        // this error mapper can be overriden by specifying value in the annotation
        @GrpcExceptionHandler
        public Status handle(StatusRuntimeException e) {
            return e.getStatus();
        }
    }

}
