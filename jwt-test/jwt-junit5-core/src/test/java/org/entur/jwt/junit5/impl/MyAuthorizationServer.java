package org.entur.jwt.junit5.impl;

import org.entur.jwt.junit5.AuthorizationServer;

import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Repeatable;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.TYPE)
@Repeatable(MyAuthorizationServer.List.class)
@Inherited
@AuthorizationServer(value = "myServer")
public @interface MyAuthorizationServer {

    public String namespace() default "";

    @Retention(RetentionPolicy.RUNTIME)
    @Target({ ElementType.TYPE })
    @Inherited
    @interface List {
        MyAuthorizationServer[] value();
    }
}
