package org.entur.jwt.junit5.headers;

import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 *
 * Annotation for the algorithm (alg) header. The default algorithm is RS256.
 * <br>
 * The authorization server signs tokens with an RSA key (RS256, RS384, RS512, PS256, PS384 and PS512)
 * or an elliptic curve key (ES256, ES384 and ES512), all of which are published in the JSON Web Keys.
 * Other algorithms (HS256, EdDSA, none and so on) are not supported; creating the token fails.
 *
 */

@Retention(RetentionPolicy.RUNTIME)
@Target({ ElementType.PARAMETER, ElementType.TYPE })
@Inherited
public @interface AlgorithmHeader {

    // alg
    public String value();

}
