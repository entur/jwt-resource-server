package org.entur.jwt.spring.filter;

import java.io.Serializable;
import java.util.Map;

import org.entur.jwt.verifier.JwtException;

public class DefaultJwtDetailsMapper implements JwtDetailsMapper {

    @Override
    public Serializable getDetails(Object request, Map<String, Object> claims) throws JwtException {
        return null;
    }

}
