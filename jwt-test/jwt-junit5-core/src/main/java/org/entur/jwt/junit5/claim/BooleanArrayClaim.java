package org.entur.jwt.junit5.claim;

import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Repeatable;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.PARAMETER, ElementType.TYPE})
@Repeatable(BooleanArrayClaim.List.class)
@Inherited
public @interface BooleanArrayClaim {

	public String name();
	public boolean[] value() default {};

    @Retention(RetentionPolicy.RUNTIME)
    @Target({ElementType.PARAMETER})
    @Inherited
    @interface List {
    	BooleanArrayClaim[] value();
    }	
}
