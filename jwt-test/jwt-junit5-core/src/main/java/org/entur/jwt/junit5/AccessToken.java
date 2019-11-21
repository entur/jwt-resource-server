package org.entur.jwt.junit5;

import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import org.entur.jwt.junit5.impl.DefaultAccessTokenEncoder;

@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.PARAMETER, ElementType.TYPE})
@Inherited
public @interface AccessToken {

	public String by() default "";

	public String subject() default "";
	
	public long issuedAt() default 0;
	public long expiresAt() default 10 * 60;

	public String authorizedParty() default "";
	public String[] audience() default {};

	public String[] scope() default {};
	
	public Class<? extends AccessTokenEncoder> encoder() default DefaultAccessTokenEncoder.class;

}
