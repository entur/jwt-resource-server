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
 * Tokens are always signed using the authorization server's RSA key, which is published in the JSON Web Keys
 * with algorithm RS256. So when validated by the resource server modules of this project (which require the algorithm
 * of the key to match the header):
 * <ul>
 * <li>RS256 tokens are accepted.</li>
 * <li>RS384, RS512, PS256, PS384 and PS512 tokens are signed, but rejected.</li>
 * <li>Other algorithms (ES256, HS256, EdDSA, none and so on) are not supported; creating the token fails.</li>
 * </ul>
 *
 */

@Retention(RetentionPolicy.RUNTIME)
@Target({ ElementType.PARAMETER, ElementType.TYPE })
@Inherited
public @interface AlgorithmHeader {

    // alg
    public String value();

}
