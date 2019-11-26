package org.entur.jwt.jwk.connect2id;

import java.util.List;

import org.entur.jwt.jwk.JwksException;
import org.entur.jwt.jwk.JwksProvider;
import org.entur.jwt.jwk.JwksUnavailableException;

import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.RemoteKeySourceException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

public class EnturJWKSource<C extends SecurityContext> implements JWKSource<C> {

	private final JwksProvider<JWK> provider;

	public EnturJWKSource(JwksProvider<JWK> provider) {
		super();
		this.provider = provider;
	}

	@Override
	public List<JWK> get(JWKSelector jwkSelector, C context) throws KeySourceException {
		try {
			List<JWK> select = jwkSelector.select(new JWKSet(provider.getJwks(false)));
			if(select.isEmpty()) {
				select = jwkSelector.select(new JWKSet(provider.getJwks(true)));
			}
			return select;
		} catch(JwksUnavailableException e) {
			throw new RemoteKeySourceException("Unable to get keys", e);
		} catch (JwksException e) {
			throw new KeySourceException("Unable to get keys", e);
		}
	}

}
