package org.entur.jwt.junit5.entur.test.auth0;

import org.entur.jwt.junit5.AuthorizationServer;

import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Repeatable;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.TYPE)
@Repeatable(PartnerAuth0AuthorizationServer.List.class)
@Inherited
@AuthorizationServer(value = "partner-auth0", encoder = PartnerAuth0AuthorizationServerEncoder.class)
public @interface PartnerAuth0AuthorizationServer {

    public String namespace() default "https://entur.io/";

    @Retention(RetentionPolicy.RUNTIME)
    @Target({ ElementType.TYPE })
    @Inherited
    @interface List {
        PartnerAuth0AuthorizationServer[] value();
    }
}
