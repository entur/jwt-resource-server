package org.entur.jwt.junit5;

import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Repeatable;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import org.entur.jwt.junit5.extention.AuthorizationServerExtension;
import org.entur.jwt.junit5.impl.DefaultAuthorizationServerEncoder;
import org.junit.jupiter.api.extension.ExtendWith;

@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.TYPE)
@Repeatable(AuthorizationServer.List.class)
@Inherited
@ExtendWith(AuthorizationServerExtension.class)
public @interface AuthorizationServer {

	public String value() default "";
	
	public Class<? extends AuthorizationServerEncoder> encoder() default DefaultAuthorizationServerEncoder.class;
	
    @Retention(RetentionPolicy.RUNTIME)
    @Target({ElementType.TYPE})
    @Inherited
    @interface List {
    	AuthorizationServer[] value();
    }
}
