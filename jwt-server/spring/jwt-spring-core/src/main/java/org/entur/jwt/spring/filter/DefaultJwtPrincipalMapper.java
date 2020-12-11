package org.entur.jwt.spring.filter;

import java.util.Map;

import org.entur.jwt.verifier.JwtException;

public class DefaultJwtPrincipalMapper implements JwtPrincipalMapper {

    protected static final String CLAIM_SUBJECT = "sub";
    protected static final String CLAIM_ISSUER = "iss";
    
    @Override
    public JwtIssuerSubjectPrincipal getPrincipal(Map<String, Object> claims) throws JwtException {
        return new JwtIssuerSubjectPrincipal((String)claims.get(CLAIM_ISSUER), (String)claims.get(CLAIM_SUBJECT));
    }

}
