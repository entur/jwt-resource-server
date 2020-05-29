package org.entur.jwt.junit5.entur.test.auth0;

import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import org.entur.jwt.junit5.AccessToken;
import org.entur.jwt.junit5.entur.test.PartnerAuth0TokenEncoder;

@Retention(RetentionPolicy.RUNTIME)
@Target({ ElementType.PARAMETER, ElementType.TYPE })
@Inherited
@AccessToken(by = "partner-auth0", audience = "https://auth0.partner.mock.audience", subject = "partnerMockSubject", encoder = PartnerAuth0TokenEncoder.class)
public @interface PartnerAuth0Token {

    public long organisationId();

    public String[] permissions() default {};

    public String[] scopes() default {};

}
