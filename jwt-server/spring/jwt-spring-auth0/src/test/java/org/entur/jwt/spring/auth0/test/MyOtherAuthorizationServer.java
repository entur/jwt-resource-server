package org.entur.jwt.spring.auth0.test;

import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Repeatable;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import org.entur.jwt.junit5.AuthorizationServer;

@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.TYPE)
@Repeatable(MyOtherAuthorizationServer.List.class)
@Inherited
@AuthorizationServer(value = "myServer", encoder = MyAuthorizationServerEncoder.class)
public @interface MyOtherAuthorizationServer {

    public String namespace() default "";

    @Retention(RetentionPolicy.RUNTIME)
    @Target({ ElementType.TYPE })
    @Inherited
    @interface List {
        MyOtherAuthorizationServer[] value();
    }
}
