package org.entur.jwt.spring.actuate;

import org.entur.jwt.jwk.JwksHealth;
import org.entur.jwt.verifier.JwtVerifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.actuate.health.AbstractHealthIndicator;
import org.springframework.boot.actuate.health.Health;

/**
 * 
 * Health indicator.
 * 
 */

public class JwksHealthIndicator extends AbstractHealthIndicator {

	protected static final Logger logger = LoggerFactory.getLogger(JwksHealthIndicator.class);

	private final JwtVerifier<?> jwtVerifier;

	public JwksHealthIndicator(JwtVerifier<?> jwtVerifier) {
		this.jwtVerifier = jwtVerifier;
	}

	@Override
	protected void doHealthCheck(Health.Builder builder) throws Exception {
		JwksHealth health = jwtVerifier.getHealth(true);

		if(health.isSuccess()) {
			builder.up();
		} else {
			builder.down();
		}
		builder.withDetail("timestamp", health.getTimestamp());
	}

}