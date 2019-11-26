package org.entur.jwt.jwk;

import java.util.List;
import java.util.Objects;

/**
 * Jwk provider extracts a key from an underlying {@linkplain JwksProvider}.
 */

public class DefaultJwkProvider<T> extends BaseJwksProvider<T> implements JwkProvider<T> {

	private final JwkFieldExtractor<T> fieldExtractor;
	/**
	 * Creates a new provider.
	 *
	 * @param provider source of jwks.
	 * @param fieldExtractor field extractor
	 */
	public DefaultJwkProvider(final JwksProvider<T> provider, JwkFieldExtractor<T> fieldExtractor) {
		super(provider);
		this.fieldExtractor = fieldExtractor;
	}

	@Override
	public T getJwk(final String keyId) throws JwksException {

		T jwk = getJwk(keyId, provider.getJwks(false));
		if(jwk == null) {
			// refresh if unknown key
			jwk = getJwk(keyId, provider.getJwks(true));
		}
		if(jwk != null) {
			return jwk;
		}
		List<T> jwks = getJwks(false);
		StringBuilder builder = new StringBuilder();
		for(T t: jwks) {
			builder.append(fieldExtractor.getJwkId(t));
			builder.append(", ");
		}
		if(builder.length() > 0) {
			builder.setLength(builder.length() - 2);
		}
		throw new JwkNotFoundException("No key found for key id " + keyId + ", only have " + builder);
	}

	protected T getJwk(String keyId, List<T> jwks) {
		for (T jwk : jwks) {
			if (Objects.equals(keyId, fieldExtractor.getJwkId(jwk))) {
				return jwk;
			}
		} 
		return null;
	}

	@Override
	public List<T> getJwks(boolean forceUpdate) throws JwksException {
		return provider.getJwks(forceUpdate);
	}

}
