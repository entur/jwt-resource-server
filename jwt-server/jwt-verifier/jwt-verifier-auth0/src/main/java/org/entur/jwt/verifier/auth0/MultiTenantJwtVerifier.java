package org.entur.jwt.verifier.auth0;

import com.auth0.jwt.JWT;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.entur.jwt.jwk.JwksException;
import org.entur.jwt.jwk.JwksHealth;
import org.entur.jwt.jwk.JwksProvider;
import org.entur.jwt.verifier.JwtException;
import org.entur.jwt.verifier.JwtVerifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Closeable;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

public class MultiTenantJwtVerifier implements JwtVerifier<DecodedJWT>, Closeable {

    protected static final Logger logger = LoggerFactory.getLogger(MultiTenantJwtVerifier.class);

    private final Map<String, CloseableJWTVerifier> verifiers;
    private final List<JwksProvider<?>> healthProviders;

    /**
     * Construct new instance.
     * 
     * @param verifiers map of verifiers which must be thread safe for read access.
     */

    public MultiTenantJwtVerifier(Map<String, CloseableJWTVerifier> verifiers) {
        this(verifiers, null);
    }

    public MultiTenantJwtVerifier(Map<String, CloseableJWTVerifier> verifiers, List<JwksProvider<?>> healthProviders) {
        this.verifiers = verifiers;
        this.healthProviders = healthProviders;
    }

    @Override
    public DecodedJWT verify(String token) throws JwksException, JwtException {
        DecodedJWT decode;
        try {
            decode = JWT.decode(token); // i.e. no signature verification, just parsing
        } catch (Exception e) {
            // assume garbage from the internet
            // TODO make logging details like this configurable, as it might be spamming and/or containing sensitive values
            logger.debug("Unable to decode token header {}", token);
            return null;
        }

        String issuer = decode.getIssuer();
        if (issuer != null) {
            CloseableJWTVerifier jwtVerifier = verifiers.get(issuer);

            if (jwtVerifier != null) {
                // so most likely not garbage from the internet
                try {
                    return jwtVerifier.verify(decode);
                } catch (SigningKeyUnavailableException e) {
                    // something is wrong on our side
                    throw new org.entur.jwt.jwk.JwksUnavailableException(e);
                } catch (JWTVerificationException e) {
                    // something was wrong with the token
                    logger.debug("Unable to verify token for known issuer {}", issuer, e);
                    return null;
                }
            }
        }
        // assume garbage from the internet
        return null;
    }

    /**
     * As long as at least one {@linkplain JwksProvider} is in good health, return
     * success health. Handle partial service level using
     * {@linkplain SigningKeyUnavailableException}. <br>
     * <br>
     */

    @Override
    public JwksHealth getHealth(boolean refresh) {
        long latestTimestamp = -1L;
        boolean atLeastOneSuccess = false;
        for (JwksProvider<?> provider : healthProviders) {
            JwksHealth status = provider.getHealth(refresh);
            if (status.isSuccess()) {
                atLeastOneSuccess = true;
            }
            latestTimestamp = Math.max(latestTimestamp, status.getTimestamp());
        }

        return new JwksHealth(latestTimestamp, atLeastOneSuccess);
    }

    @Override
    public void close() throws IOException {
        for (Entry<String, CloseableJWTVerifier> entry : verifiers.entrySet()) {
            CloseableJWTVerifier value = entry.getValue();
            try {
                value.close();
            } catch(IOException e) {
                // ignore
            }
        }
    }
}
