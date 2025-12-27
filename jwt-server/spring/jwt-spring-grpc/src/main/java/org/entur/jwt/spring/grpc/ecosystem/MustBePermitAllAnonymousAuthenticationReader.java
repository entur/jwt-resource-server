package org.entur.jwt.spring.grpc.ecosystem;

import io.grpc.Metadata;
import io.grpc.MethodDescriptor;
import io.grpc.ServerCall;
import net.devh.boot.grpc.server.security.authentication.AnonymousAuthenticationReader;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;
import java.util.List;
import java.util.Map;

public class MustBePermitAllAnonymousAuthenticationReader extends AnonymousAuthenticationReader {

    protected final Map<String, List<String>> serviceNameMethodName;

    public MustBePermitAllAnonymousAuthenticationReader(String key, Map<String, List<String>> serviceNameMethodName) {
        super(key);
        this.serviceNameMethodName = serviceNameMethodName;
    }

    public MustBePermitAllAnonymousAuthenticationReader(String key, Object principal, Collection<? extends GrantedAuthority> authorities, Map<String, List<String>> serviceNameMethodName) {
        super(key, principal, authorities);
        this.serviceNameMethodName = serviceNameMethodName;
    }

    @Override
    public Authentication readAuthentication(ServerCall<?, ?> call, Metadata headers) {
        if(acceptAnon(call)) {
            return super.readAuthentication(call, headers);
        }
        throw new AuthenticationCredentialsNotFoundException("Method " + call.getMethodDescriptor().getFullMethodName() + " requires authentication");
    }

    private boolean acceptAnon(ServerCall<?, ?> call) {
        MethodDescriptor<?, ?> method = call.getMethodDescriptor();

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
        return false;
    }
}
