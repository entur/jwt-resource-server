package org.entur.jwt.client.properties;

public class JwtClientProperties {

	protected JwtHealthIndicator healthIndicator = new JwtHealthIndicator();
	
	protected Auth0JwtClientProperties auth0 = new Auth0JwtClientProperties();

	protected KeycloakJwtClientProperties keycloak = new KeycloakJwtClientProperties();

	public void setHealthIndicator(JwtHealthIndicator healthIndicator) {
		this.healthIndicator = healthIndicator;
	}
	
	public JwtHealthIndicator getHealthIndicator() {
		return healthIndicator;
	}

	public Auth0JwtClientProperties getAuth0() {
		return auth0;
	}

	public void setAuth0(Auth0JwtClientProperties auth0) {
		this.auth0 = auth0;
	}

	public KeycloakJwtClientProperties getKeycloak() {
		return keycloak;
	}

	public void setKeycloak(KeycloakJwtClientProperties keycloak) {
		this.keycloak = keycloak;
	}

	
	
}
