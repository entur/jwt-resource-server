package org.entur.jwt.spring.grpc.exception;

import io.grpc.ServerCall;

public interface ServerCallRuntimeExceptionTranslator {

	/**
	 * Translate exception to close type response.
	 * 
	 * @param <ReqT> request type
	 * @param <RespT> response type
	 * @param serverCall call to close
	 * @param e exception
	 * @return true if handled
	 */
	
	<ReqT, RespT> boolean close(ServerCall<ReqT, RespT> serverCall, RuntimeException e);
}
