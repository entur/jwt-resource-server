package org.entur.jwt.junit5.entur.test.auth0;

import org.entur.jwt.junit5.headers.KeyIdHeader;

import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Retention(RetentionPolicy.RUNTIME)
@Target({ ElementType.PARAMETER, ElementType.TYPE })
@Inherited
@PartnerAuth0Token(organisationId = 0)
@KeyIdHeader("unknown-kid")
public @interface UnknownKeyIdPartnerAuth0Token {
}
