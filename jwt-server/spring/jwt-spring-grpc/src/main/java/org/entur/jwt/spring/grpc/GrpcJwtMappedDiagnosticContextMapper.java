package org.entur.jwt.spring.grpc;

import java.util.Map;
import java.util.Map.Entry;

import org.entur.jwt.spring.filter.log.JwtMappedDiagnosticContextMapper;
import org.entur.jwt.verifier.JwtClaimException;
import org.slf4j.MDC;

import io.grpc.Context;

public class GrpcJwtMappedDiagnosticContextMapper<T> implements JwtMappedDiagnosticContextMapper<T> {

    protected static final Context.Key<Object> CONTEXT = Context.key("REQUEST_JWT_CONTEXT"); 

    private JwtMappedDiagnosticContextMapper<T> delegate;
    
    public GrpcJwtMappedDiagnosticContextMapper(JwtMappedDiagnosticContextMapper<T> delegate) {
        this.delegate = delegate;
    }

    public <ReqT, RespT> Context createContext(T token) throws JwtClaimException {
        Map<String, String> map = getContext(token);
        
        return Context.current().withValue(CONTEXT, map);
    }
    
    public static void addContext() {
        Map<String, String> map = (Map<String, String>) CONTEXT.get();
        for (Entry<String, String> entry : map.entrySet()) {
            MDC.put(entry.getKey(), entry.getValue());
        }
    }
    
    public static void removeContext() {
        Map<String, String> map = (Map<String, String>) CONTEXT.get();
        for (Entry<String, String> entry : map.entrySet()) {
            MDC.remove(entry.getKey());
        }
    }

    @Override
    public Map<String, String> getContext(T token) throws JwtClaimException {
        return delegate.getContext(token);
    }

    @Override
    public void addContext(T token) throws JwtClaimException {
        delegate.addContext(token);
    }

    @Override
    public void removeContext(T token) {
        delegate.removeContext(token);
    }
  
}
