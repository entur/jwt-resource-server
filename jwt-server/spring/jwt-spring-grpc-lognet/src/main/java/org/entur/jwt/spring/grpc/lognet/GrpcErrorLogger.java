package org.entur.jwt.spring.grpc.lognet;

import io.grpc.Status;
import org.entur.jwt.spring.AbstractConfigurableLogger;
import org.lognet.springboot.grpc.recovery.GRpcExceptionScope;
import org.slf4j.Logger;
import org.slf4j.event.Level;

public class GrpcErrorLogger extends AbstractConfigurableLogger {


    public GrpcErrorLogger(String loggerName, String levelName, boolean stackTrace) {
        super(loggerName, levelName, stackTrace);
    }

    public GrpcErrorLogger(Logger logger, Level level, boolean stackTrace) {
        super(logger, level, stackTrace);
    }

    public void handle(Exception e, Status status, GRpcExceptionScope scope) {
        if(enabled.getAsBoolean()) {
            logger.accept("Got error with status " + status.getCode().name(), e);
        }
    }
}
