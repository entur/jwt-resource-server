package org.entur.jwt.verifier;

import java.util.Map;

import org.entur.jwt.verifier.config.JwtClaimsProperties;
import org.entur.jwt.verifier.config.JwkProperties;
import org.entur.jwt.verifier.config.JwtTenantProperties;

public interface JwtVerifierFactory<T> {

    JwtVerifier<T> getVerifier(Map<String, JwtTenantProperties> tenants, JwkProperties jwk, JwtClaimsProperties claims);
}
