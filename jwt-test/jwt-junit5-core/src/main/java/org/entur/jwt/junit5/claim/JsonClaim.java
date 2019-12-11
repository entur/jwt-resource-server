package org.entur.jwt.junit5.claim;

import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Repeatable;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * 
 * Raw JSON claim.
 * 
 */

@Retention(RetentionPolicy.RUNTIME)
@Target({ ElementType.PARAMETER, ElementType.TYPE })
@Repeatable(JsonClaim.List.class)
@Inherited
public @interface JsonClaim {

    public String name(); // claim name / root key to set in body JSON document

    public String value(); // value to embed as-is (without encoding)

    @Retention(RetentionPolicy.RUNTIME)
    @Target({ ElementType.PARAMETER })
    @Inherited
    @interface List {
        JsonClaim[] value();
    }
}
