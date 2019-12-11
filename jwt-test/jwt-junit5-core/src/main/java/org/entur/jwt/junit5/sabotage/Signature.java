package org.entur.jwt.junit5.sabotage;

import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Retention(RetentionPolicy.RUNTIME)
@Target({ ElementType.PARAMETER, ElementType.TYPE })
@Inherited
public @interface Signature {

    public String value() default "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

}
