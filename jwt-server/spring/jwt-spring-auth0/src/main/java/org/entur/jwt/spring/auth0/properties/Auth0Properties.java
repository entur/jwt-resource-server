package org.entur.jwt.spring.auth0.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "entur.jwt.auth0")
public class Auth0Properties {

	private Auth0AuthorityMapperProperties authorityMapper = new Auth0AuthorityMapperProperties();
	
	/** claim namespace (for custom claims) */
	private String namespace;

	public String getNamespace() {
		return namespace;
	}

	public void setNamespace(String namespace) {
		this.namespace = namespace;
	}

	public void setAuthorityMapper(Auth0AuthorityMapperProperties authorityMapper) {
		this.authorityMapper = authorityMapper;
	}
	
	public Auth0AuthorityMapperProperties getAuthorityMapper() {
		return authorityMapper;
	}
	
}
