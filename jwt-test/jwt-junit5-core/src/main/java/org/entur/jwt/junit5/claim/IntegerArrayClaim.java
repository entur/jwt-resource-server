package org.entur.jwt.junit5.claim;

import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Repeatable;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Integer as in whole numbers; for int or long types.
 *
 */

@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.PARAMETER, ElementType.TYPE})
@Repeatable(IntegerArrayClaim.List.class)
@Inherited
public @interface IntegerArrayClaim {

	public String name();
	public long[] value() default {};

    @Retention(RetentionPolicy.RUNTIME)
    @Target({ElementType.PARAMETER})
    @Inherited
    @interface List {
    	IntegerArrayClaim[] value();
    }
}
