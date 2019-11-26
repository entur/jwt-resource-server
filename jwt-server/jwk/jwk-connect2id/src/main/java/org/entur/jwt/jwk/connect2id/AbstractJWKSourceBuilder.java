package org.entur.jwt.jwk.connect2id;

import org.entur.jwt.jwk.AbstractJwksProviderBuilder;
import org.entur.jwt.jwk.JwksProvider;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

/**
 * JwkProvider builder scaffold.
 * 
 * @see <a href="https://www.sitepoint.com/self-types-with-javas-generics/">https://www.sitepoint.com/self-types-with-javas-generics/</a> 
 */

public abstract class AbstractJWKSourceBuilder<C extends SecurityContext, B extends AbstractJWKSourceBuilder<C, B>> extends AbstractJwksProviderBuilder<JWK, B> {

	public AbstractJWKSourceBuilder(JwksProvider<JWK> jwksProvider) {
		super(jwksProvider);
	}

	/**
	 * Creates a {@link JWKSource}
	 *
	 * @return a newly created {@link JWKSource}
	 */
	public JWKSource<C> build() {
		return new EnturJWKSource<>(build(jwksProvider));

	}
}
