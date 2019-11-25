package org.entur.jwt.spring.rest.config;

import java.util.Map;
import java.util.function.BiFunction;

public class TenantArgumentResolver implements BiFunction<Map<String, Object>, Class<?>, Tenant> {

	@Override
	public Tenant apply(Map<String, Object> t, Class<?> u) {
		Number value = (Number) t.get("organisationID");
		if(value == null) {
			throw new IllegalArgumentException();
		}
		if(u == Tenant.class) {
			return new Tenant(value.longValue());
		}
		if(u == PartnerTenant.class) {
			return new PartnerTenant(value.longValue());
		}
		throw new RuntimeException();
	}

}
