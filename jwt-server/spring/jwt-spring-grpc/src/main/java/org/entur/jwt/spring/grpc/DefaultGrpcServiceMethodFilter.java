package org.entur.jwt.spring.grpc;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import io.grpc.MethodDescriptor;
import io.grpc.ServerCall;

public class DefaultGrpcServiceMethodFilter implements GrpcServiceMethodFilter {

	private Set<String> services = new HashSet<>();
	
	private Map<String, Set<String>> methods = new HashMap<>();
	
	public void addService(String service) {
		this.services.add(service);
	}

	public void addServiceMethod(String service, String method) {
		Set<String> set = methods.get(service);
		if(set == null) {
			set = new HashSet<>();
			methods.put(service, set);
		}
		set.add(method);
	}

	@Override
	public <ReqT, RespT> boolean matches(ServerCall<ReqT, RespT> call) {
		// first check per service
		MethodDescriptor<ReqT,RespT> methodDescriptor = call.getMethodDescriptor();

		String serviceName = methodDescriptor.getServiceName();
		if(services.contains(serviceName)) {
			return true;
		}
		
		// then per method
		Set<String> set = methods.get(serviceName);
		return set != null && set.contains(methodDescriptor.getBareMethodName());
	}
	
}
