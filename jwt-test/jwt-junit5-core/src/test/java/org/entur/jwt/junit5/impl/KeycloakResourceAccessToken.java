package org.entur.jwt.junit5.impl;

import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import org.entur.jwt.junit5.AccessToken;
import org.entur.jwt.junit5.claim.MapClaim;
import org.entur.jwt.junit5.claim.MapClaim.Entry;

@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.PARAMETER, ElementType.TYPE})
@Inherited
@AccessToken(
		audience = "mock.my.partner.audience",
		by = "myServer",
		encoder = KeycloakResourceAccessTokenEncoder.class
		)
@MapClaim(path = {"resources_access", "abcdef"}, entries = {
		@Entry(name = "roles", alwaysArray = true, value = {"admin"})
})
public @interface KeycloakResourceAccessToken {
	
	public long myId();
}
