package org.entur.jwt.spring.rest.config;

import java.util.ArrayList;
import java.util.List;

import org.entur.jwt.spring.filter.JwtAuthorityMapper;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import com.auth0.jwt.impl.NullClaim;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;

public class SimpleJwtAuthorityMapper implements JwtAuthorityMapper<DecodedJWT> {

    @Override
    public List<GrantedAuthority> getGrantedAuthorities(DecodedJWT token) {
        List<GrantedAuthority> authorities = new ArrayList<>();

        Claim scopeClaim = token.getClaim("scope");
        if (scopeClaim != null && !(scopeClaim instanceof NullClaim)) {
            String[] scopes = scopeClaim.asString().split("\\s");
            for (String scope : scopes) {
                authorities.add(new SimpleGrantedAuthority(scope));
            }
        }
        return authorities;
    }

}
