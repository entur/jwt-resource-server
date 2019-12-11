package org.entur.jwt.spring.filter.log;

import java.util.List;

import org.entur.jwt.verifier.JwtClaimException;
import org.entur.jwt.verifier.JwtClaimExtractor;
import org.slf4j.MDC;

public class DefaultJwtMappedDiagnosticContextMapper<T> implements JwtMappedDiagnosticContextMapper<T> {

    /** claim keys */
    private final String[] from;
    /** mdc keys */
    private final String[] to;

    private final JwtClaimExtractor<T> extractor;

    public DefaultJwtMappedDiagnosticContextMapper(List<String> claims, List<String> keys, JwtClaimExtractor<T> extractor) {
        this.from = claims.toArray(new String[claims.size()]);
        this.to = keys.toArray(new String[claims.size()]);
        this.extractor = extractor;
    }

    public void addContext(T token) throws JwtClaimException {
        for (int i = 0; i < from.length; i++) {
            String value = extractor.getClaim(token, from[i], String.class);
            if (value != null) {
                MDC.put(to[i], value);
            }
        }
    }

    public void removeContext(T token) {
        for (int i = 0; i < to.length; i++) {
            MDC.remove(to[i]);
        }
    }
}
