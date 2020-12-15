package org.entur.jwt.verifier.auth0;

import java.io.Closeable;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import com.auth0.jwt.exceptions.InvalidClaimException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;

/**
 * 
 * Auth0 verifier cannot handle verification of audiences against a list. <br>
 * <br>
 * In addition, this verifies that an audience exists at all (which it must),
 * even if no specific audience is required. <br>
 * <br>
 * See https://github.com/auth0/java-jwt/pull/290 and
 * https://github.com/auth0/java-jwt/issues/256. <br>
 * <br>
 * Retire this class when Auth0 supports this function.
 */

public class AudienceJWTVerifier implements CloseableJWTVerifier {

    private final JWTVerifier delegate;
    private final Closeable closeable;
    private final List<String> audiences;

    public AudienceJWTVerifier(JWTVerifier delegate, Closeable closeable, List<String> audiences) {
        super();
        this.delegate = delegate;
        this.closeable = closeable;
        if (audiences != null && !audiences.isEmpty()) {
            this.audiences = new ArrayList<>(audiences); // defensive copy for read-only multi-threading support
        } else {
            this.audiences = null;
        }
    }

    public DecodedJWT verify(String token) {
        DecodedJWT decodedJWT = delegate.verify(token);

        return verify(decodedJWT);
    }

    public DecodedJWT verify(DecodedJWT jwt) {
        DecodedJWT decodedJWT = delegate.verify(jwt);

        List<String> jwtAudiences = decodedJWT.getAudience();
        if (jwtAudiences == null || jwtAudiences.isEmpty()) {
            throw new InvalidClaimException("No audience specified in JWT.");
        }

        // if there is a list of approved audiences, check that at least one of the JWT
        // audiences is among them
        if (audiences != null && Collections.disjoint(audiences, jwtAudiences)) {
            throw new InvalidClaimException("None of the claim 'aud' value '" + jwtAudiences + "' is not amoung the required audiences.");
        }
        return decodedJWT;
    }

    @Override
    public void close() throws IOException {
        closeable.close();
    }

}
