package org.entur.jwt.junit5.claim;

import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Repeatable;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Retention(RetentionPolicy.RUNTIME)
@Target({ ElementType.PARAMETER, ElementType.TYPE })
@Repeatable(Scope.List.class)
@Inherited
public @interface Scope {

    public String[] value() default {};

    @Retention(RetentionPolicy.RUNTIME)
    @Target({ ElementType.PARAMETER })
    @Inherited
    @interface List {
        Scope[] value();
    }
}
