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
@Repeatable(MyAuthorizationServer.List.class)
@Inherited
@AuthorizationServer(value = "myServer", encoder = MyAuthorizationServerEncoder.class)
public @interface MyAuthorizationServer {

    public String namespace() default "";

    @Retention(RetentionPolicy.RUNTIME)
    @Target({ ElementType.TYPE })
    @Inherited
    @interface List {
        MyAuthorizationServer[] value();
    }
}
