package org.entur.jwt.spring;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import reactor.core.publisher.Mono;

import java.util.List;

/**
 * Workaround adapter for wrapping synchronized implementation
 */
public class ReactiveJWKSourceAdapter {

	private final JWKSource<SecurityContext> source;

	/**
	 * Creates a new instance
	 *
	 * @param source
	 */
	public ReactiveJWKSourceAdapter(JWKSource<SecurityContext> source) {
		this.source = source;
	}

	public Mono<List<JWK>> get(JWKSelector jwkSelector) {
		return Mono.fromCallable(() -> this.source.get(jwkSelector, null));
	}

}
