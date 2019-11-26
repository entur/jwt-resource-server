package org.entur.jwt.jwk.connect2id;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.util.List;

import org.entur.jwt.jwk.InvalidSigningKeysException;
import org.entur.jwt.jwk.JwksReader;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.util.IOUtils;


public class Connect2IdJwkReader implements JwksReader<JWK> {

	@Override
	public List<JWK> readJwks(InputStream inputStream) throws IOException, InvalidSigningKeysException {
		String content = IOUtils.readInputStreamToString(inputStream, StandardCharsets.UTF_8);

		JWKSet parse;
		try {
			parse = JWKSet.parse(content);
		} catch (ParseException e) {
			throw new InvalidSigningKeysException("Unable to parse keys", e);
		}

		return parse.getKeys();
	}

}
