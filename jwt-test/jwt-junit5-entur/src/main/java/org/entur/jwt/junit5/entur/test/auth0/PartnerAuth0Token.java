package org.entur.jwt.junit5.entur.test.auth0;

import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import org.entur.jwt.junit5.AccessToken;
import org.entur.jwt.junit5.claim.Audience;
import org.entur.jwt.junit5.claim.Subject;
import org.entur.jwt.junit5.entur.test.PartnerAuth0TokenEncoder;

@Retention(RetentionPolicy.RUNTIME)
@Target({ ElementType.PARAMETER, ElementType.TYPE })
@Inherited
@AccessToken(by = "partner-auth0", encoder = PartnerAuth0TokenEncoder.class)
public @interface PartnerAuth0Token {

    public long organisationId();

    public String[] permissions() default {};

    public String[] scopes() default {};
    
    /**
     * Subject 'overloaded' for convenience.
     * 
     * @see Subject annotation
     * 
     * @return audiences
     */
    
    public String subject() default "partnerMockSubject";

    /**
     * Audience 'overloaded' for convenience.
     * 
     * @see Audience annotation
     *
     * @return audiences
     */

    public String[] audience() default "https://auth0.partner.mock.audience";

}
