package org.entur.jwt.spring.grpc.ecosystem;

import io.grpc.MethodDescriptor;
import io.grpc.ServerCall;
import net.devh.boot.grpc.server.security.check.AccessPredicate;
import org.springframework.security.core.Authentication;

import java.util.List;
import java.util.Map;

public class MustBePermitAllAnonymousOrFullyAuthenticatedAccessPredicate implements AccessPredicate {

    protected final Map<String, List<String>> serviceNameMethodName;

    public MustBePermitAllAnonymousOrFullyAuthenticatedAccessPredicate(Map<String, List<String>> serviceNameMethodName) {
        this.serviceNameMethodName = serviceNameMethodName;
    }

    @Override
    public boolean test(Authentication authentication, ServerCall<?, ?> serverCall) {
        MethodDescriptor<?, ?> method = serverCall.getMethodDescriptor();

        String lowerCaseServiceName = method.getServiceName().toLowerCase();
        List<String> methodNames = serviceNameMethodName.get(lowerCaseServiceName);
        if (methodNames != null) {
            if (methodNames.contains("*")) {
                return true;
            }

            String lowerCaseBareMethodName = method.getBareMethodName().toLowerCase();
            String lowerCaseFullMethodName = method.getFullMethodName().toLowerCase();

            if (methodNames.contains(lowerCaseBareMethodName) || methodNames.contains(lowerCaseFullMethodName)) {
                return true;
            }
        }

        return AccessPredicate.fullyAuthenticated().test(authentication, serverCall);
    }
}
