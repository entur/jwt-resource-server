package org.entur.jwt.spring.grpc.exception;

import io.grpc.Metadata;
import io.grpc.ServerCall;
import io.grpc.StatusRuntimeException;
import io.grpc.util.TransmitStatusRuntimeExceptionInterceptor;

/**
 * Translate {@linkplain StatusRuntimeException} to status responses.<br><br>
 * 
 * According to {@linkplain TransmitStatusRuntimeExceptionInterceptor}, it might might leak some details in metadata / status,
 * whereas this class only returns plain status codes.
 */

public class ServerCallStatusRuntimeExceptionTranslator implements ServerCallRuntimeExceptionTranslator {

	@Override
	public <ReqT, RespT> boolean close(ServerCall<ReqT, RespT> serverCall, RuntimeException e) {
		if(e instanceof StatusRuntimeException) {
			StatusRuntimeException statusRuntimeException = (StatusRuntimeException)e;
	        serverCall.close(statusRuntimeException.getStatus(), new Metadata());
	        
	        return true;
		}
		return false;
	}

}
