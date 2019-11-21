package org.entur.jwt.jwk.connect2id;

import org.entur.jwt.jwk.JwkFieldExtractor;

import com.nimbusds.jose.jwk.JWK;

public class Connect2IdJwkFieldExtractor implements JwkFieldExtractor<JWK> {

	@Override
	public String getJwkId(JWK jwk) {
		return jwk.getKeyID();
	}

}
