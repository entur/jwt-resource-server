package org.entur.jwt.junit5.claim;

import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Repeatable;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Retention(RetentionPolicy.RUNTIME)
@Target({ ElementType.PARAMETER, ElementType.TYPE })
@Repeatable(MapClaim.List.class)
@Inherited
public @interface MapClaim {

    public String[] path();

    public Entry[] entries() default {};

    @Retention(RetentionPolicy.RUNTIME)
    @Target({ ElementType.PARAMETER })
    @Inherited
    @interface List {
        MapClaim[] value();
    }

    @Retention(RetentionPolicy.RUNTIME)
    @Target({ ElementType.PARAMETER, ElementType.TYPE })
    @Inherited
    public @interface Entry {

        public String name();

        public Class<?> type() default String.class;

        public String[] value() default {};

        public boolean alwaysArray() default false;
    }

}
