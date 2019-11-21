package org.entur.jwt.junit5.entur.test.organsation;

import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Repeatable;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import org.entur.jwt.junit5.AuthorizationServer;

@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.TYPE)
@Repeatable(OrganisationAuthorizationServer.List.class)
@Inherited
@AuthorizationServer(
		value="organisation-keycloak"
)
public @interface OrganisationAuthorizationServer {

    @Retention(RetentionPolicy.RUNTIME)
    @Target({ElementType.TYPE})
    @Inherited
    @interface List {
    	OrganisationAuthorizationServer[] value();
    }
}
