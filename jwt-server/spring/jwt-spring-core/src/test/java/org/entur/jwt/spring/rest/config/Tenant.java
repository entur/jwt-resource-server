package org.entur.jwt.spring.rest.config;

public class Tenant {

	private long organisationId;

	public Tenant(long organisationId) {
		this.organisationId = organisationId;
	}

	public long getOrganisationId() {
		return organisationId;
	}
}
