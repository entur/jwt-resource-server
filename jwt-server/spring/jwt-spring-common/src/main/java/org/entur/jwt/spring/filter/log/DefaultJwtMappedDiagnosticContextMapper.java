package org.entur.jwt.spring.filter.log;

import org.slf4j.MDC;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.HashMap;
import java.util.List;
import java.util.Map;


public class DefaultJwtMappedDiagnosticContextMapper implements JwtMappedDiagnosticContextMapper {

    /** claim keys */
    protected final String[] from;
    /** mdc keys */
    protected final String[] to;

    public DefaultJwtMappedDiagnosticContextMapper(List<String> claims, List<String> keys) {
        this.from = claims.toArray(new String[0]);
        this.to = keys.toArray(new String[claims.size()]);
    }

    public Map<String, String> getContext(Jwt token){
    	Map<String, String> context = new HashMap<>();
    	
        for (int i = 0; i < from.length; i++) {
            String value = getClaimAsString(token, from[i]);
            if (value != null) {
                context.put(to[i], value);
            }
        }
        return context;
    }
    
    public void addContext(Jwt token) {
        for (int i = 0; i < from.length; i++) {
            String value = getClaimAsString(token, from[i]);
            if (value != null) {
                MDC.put(to[i], value);
            }
        }
    }

    protected String getClaimAsString(Jwt token, String claim) {
        // claims are not necessarily strings, e.g. numbers, lists or timestamps
        Object value = token.getClaim(claim);
        if (value != null) {
            return value.toString();
        }
        return null;
    }

    public void removeContext(Jwt token) {
        for (String s : to) {
            MDC.remove(s);
        }
    }
}
