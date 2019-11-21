package org.entur.jwt.spring.rest.token;

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
		audience = "mock.my.audience",
		encoder = MyAccessTokenEncoder.class
		)
public @interface MyAccessToken {
	
	public long myId();
}
