package org.entur.jwt.spring.rest.config;

import java.util.function.BiFunction;
import com.auth0.jwt.impl.NullClaim;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;

public class TenantArgumentResolver implements BiFunction<DecodedJWT, Class<?>, Tenant> {

	@Override
	public Tenant apply(DecodedJWT t, Class<?> u) {
		Claim claim = t.getClaim("organisationID");
		if(claim == null || claim instanceof NullClaim) {
			throw new IllegalArgumentException();
		}
		if(u == Tenant.class) {
			return new Tenant(claim.asLong());
		}
		if(u == PartnerTenant.class) {
			return new PartnerTenant(claim.asLong());
		}
		throw new RuntimeException();
	}

}
