package org.entur.jwt.spring.auth0.properties;

public class Auth0AuthorityMapperProperties {

	private boolean auth0 = true;
	private boolean keycloak = true;
	
	public boolean isAuth0() {
		return auth0;
	}
	public void setAuth0(boolean auth0) {
		this.auth0 = auth0;
	}
	public boolean isKeycloak() {
		return keycloak;
	}
	public void setKeycloak(boolean keycloak) {
		this.keycloak = keycloak;
	}
	
	
}
