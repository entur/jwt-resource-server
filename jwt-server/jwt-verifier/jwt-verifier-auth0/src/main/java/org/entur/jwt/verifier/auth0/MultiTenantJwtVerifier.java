package org.entur.jwt.verifier.auth0;

import java.util.List;
import java.util.Map;

import org.entur.jwt.jwk.JwksException;
import org.entur.jwt.jwk.JwksHealth;
import org.entur.jwt.jwk.JwksProvider;
import org.entur.jwt.verifier.JwtClientException;
import org.entur.jwt.verifier.JwtException;
import org.entur.jwt.verifier.JwtVerifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.JWTVerifier;
import com.auth0.jwt.exceptions.AlgorithmMismatchException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;

public class MultiTenantJwtVerifier implements JwtVerifier<DecodedJWT> {

	protected static final Logger logger = LoggerFactory.getLogger(MultiTenantJwtVerifier.class);

	private final Map<String, JWTVerifier> verifiers;
	private final List<JwksProvider<?>> healthProviders;
	
	/**
	 * Construct new instance.
	 * 
	 * @param verifiers map of verifiers which must be thread safe for read access.
	 */
	
	public MultiTenantJwtVerifier(Map<String, JWTVerifier> verifiers) {
		this(verifiers, null);
	}

	public MultiTenantJwtVerifier(Map<String, JWTVerifier> verifiers, List<JwksProvider<?>> healthProviders) {
		this.verifiers = verifiers;
		this.healthProviders = healthProviders;
	}

	@Override
	public DecodedJWT verify(String token) throws JwksException, JwtException {
		DecodedJWT decode;
		try {
			decode = JWT.decode(token); // i.e. no signature verification, just parsing
		} catch(Exception e) {
			logger.info("Unable to decode token", e);
			return null;
		}
		
		String issuer = decode.getIssuer();
		if(issuer != null) {
			JWTVerifier jwtVerifier = verifiers.get(issuer);
			
			if(jwtVerifier != null) {
				try {
					return jwtVerifier.verify(decode);
				} catch(SigningKeyUnavailableException e) {
					throw new org.entur.jwt.jwk.JwksUnavailableException(e);
				} catch(AlgorithmMismatchException e) {
					throw new JwtClientException(e); // auth0 supports most known algorithms
				} catch(JWTVerificationException e) {
					logger.info("Unable to verify token for issuer {}", issuer, e);
					return null;
				}
			} else {
				logger.info("Unknown issuer {}", issuer);
			}
		}
		
		return null;
	}

	/**
	 * As long as at least one {@linkplain JwksProvider} is in good health, return success health.
	 * Handle partial service level using {@linkplain SigningKeyUnavailableException}.
	 * <br>
	 * <br>
	 */
	
	@Override
	public JwksHealth getHealth(boolean refresh) {
		long latestTimestamp = -1L;
		boolean atLeastOneSuccess = false;
		for(JwksProvider<?> provider : healthProviders) {
			JwksHealth status = provider.getHealth(refresh); 
			if(status.isSuccess()) {
				atLeastOneSuccess = true;
			}
			latestTimestamp = Math.max(latestTimestamp, status.getTimestamp());
		}				
		
		return new JwksHealth(latestTimestamp, atLeastOneSuccess);
	}
}
