package org.entur.jwt.client;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Class that contains the Tokens obtained after a call to the authorization server.
 * 
 */

@SuppressWarnings("unused")
@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ClientCredentialsResponse {

	@JsonProperty("access_token")
	private String accessToken;
	@JsonProperty("refresh_token")
	private String refreshToken;
	@JsonProperty("token_type")
	private String tokenType;
	@JsonProperty("expires_in")
	private Long expiresIn;

	// non-standard claim - see https://github.com/keycloak/keycloak/blob/master/core/src/main/java/org/keycloak/representations/AccessTokenResponse.java
	@JsonProperty("refresh_expires_in")
	private Long refreshExpiresIn;

	/**
	 * Getter for the Auth0's access token.
	 *
	 * @return the access token or null if missing.
	 */
	@JsonProperty("access_token")
	public String getAccessToken() {
		return accessToken;
	}

	/**
	 * Getter for the Auth0's refresh token.
	 *
	 * @return the refresh token or null if missing.
	 */
	@JsonProperty("refresh_token")
	public String getRefreshToken() {
		return refreshToken;
	}

	/**
	 * Getter for the token type.
	 *
	 * @return the token type or null if missing.
	 */
	@JsonProperty("token_type")
	public String getTokenType() {
		return tokenType;
	}

	/**
	 * Getter for the duration of this token in seconds since it was issued.
	 *
	 * @return the number of seconds in which this token will expire, since the time it was issued.
	 */
	@JsonProperty("expires_in")
	public Long getExpiresIn() {
		return expiresIn;
	}

	@JsonProperty("refresh_expires_in")
	public Long getRefreshExpiresIn() {
		return refreshExpiresIn;
	}
}