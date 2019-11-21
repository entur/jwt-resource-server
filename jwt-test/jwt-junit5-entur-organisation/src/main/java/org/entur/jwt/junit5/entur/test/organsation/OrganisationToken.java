package org.entur.jwt.junit5.entur.test.organsation;

import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import org.entur.jwt.junit5.AccessToken;

@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.PARAMETER, ElementType.TYPE})
@Inherited
@AccessToken(
		audience = "https://organisation.mock.audience",
		by = "organisation-keycloak",
		encoder = OrganisationAccessTokenEncoder.class
		)
public @interface OrganisationToken {
	
	public String[] resourceAccess() default {};
	public String resource() default "myResource";
	public String[] realmAccess() default {};
	
	public String[] roles() default {};
}
