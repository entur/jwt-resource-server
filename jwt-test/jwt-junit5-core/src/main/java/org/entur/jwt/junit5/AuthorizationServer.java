package org.entur.jwt.junit5;

import org.entur.jwt.junit5.extention.AuthorizationServerExtension;
import org.entur.jwt.junit5.impl.DefaultAuthorizationServerEncoder;
import org.entur.jwt.junit5.configuration.enrich.PropertiesFileResourceLocksProvider;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.parallel.ResourceLock;

import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Repeatable;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.TYPE)
@Repeatable(AuthorizationServer.List.class)
@Inherited
@ExtendWith(AuthorizationServerExtension.class)
// test classes sharing a properties file must not run in parallel
@ResourceLock(providers = PropertiesFileResourceLocksProvider.class)
public @interface AuthorizationServer {

    public String value() default "";

    public Class<? extends AuthorizationServerEncoder> encoder() default DefaultAuthorizationServerEncoder.class;

    @Retention(RetentionPolicy.RUNTIME)
    @Target({ ElementType.TYPE })
    @Inherited
    @interface List {
        AuthorizationServer[] value();
    }
}
