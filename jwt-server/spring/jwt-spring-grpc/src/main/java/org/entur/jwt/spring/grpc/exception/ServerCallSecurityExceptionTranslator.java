package org.entur.jwt.spring.grpc.exception;

import java.util.Objects;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.util.ThrowableAnalyzer;

import io.grpc.Metadata;
import io.grpc.ServerCall;
import io.grpc.Status;

public class ServerCallSecurityExceptionTranslator implements ServerCallRuntimeExceptionTranslator {

    private final static ThrowableAnalyzer throwableAnalyzer = new ThrowableAnalyzer();

    private static Logger log = LoggerFactory.getLogger(ServerCallSecurityExceptionTranslator.class);

	@Override
	public <ReqT, RespT> boolean close(ServerCall<ReqT, RespT> serverCall, RuntimeException e) {
		Throwable[] causeChain = throwableAnalyzer.determineCauseChain(e);
        AuthenticationException authenticationException = (AuthenticationException) throwableAnalyzer.getFirstThrowableOfType(AuthenticationException.class, causeChain);

        if (Objects.nonNull(authenticationException)) {
            log.warn("Got authentication exception", e);

            serverCall.close(Status.UNAUTHENTICATED, new Metadata());
            return true;
        } else {
            AccessDeniedException accessDeniedException = (AccessDeniedException) throwableAnalyzer.getFirstThrowableOfType(AccessDeniedException.class, causeChain);
            if (Objects.nonNull(accessDeniedException)) {
                log.warn("Got permission denied exception", e);
                serverCall.close(Status.PERMISSION_DENIED, new Metadata());
                
                return true;
            } else {
            	return false;
            }
        }
	}

}
