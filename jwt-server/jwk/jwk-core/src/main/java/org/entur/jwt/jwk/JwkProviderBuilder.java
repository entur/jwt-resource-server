package org.entur.jwt.jwk;

/**
 * JwkProvider builder
 */

public class JwkProviderBuilder<T> extends AbstractJwkProviderBuilder<T, JwkProviderBuilder<T>> {

	public JwkProviderBuilder(JwksProvider<T> jwksProvider, JwkFieldExtractor<T> fieldExtractor) {
		super(jwksProvider, fieldExtractor);
	}

}
