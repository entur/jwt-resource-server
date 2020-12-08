package org.entur.jwt.spring.grpc;

import io.grpc.ServerCall;

public interface GrpcServiceMethodFilter {

	<ReqT, RespT> boolean matches(ServerCall<ReqT, RespT> call);
	
}
