package org.entur.jwt.jwk;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectReader;

public class JwkReaderImpl implements JwksReader<JwkImpl> {

	private final ObjectReader reader;

	public JwkReaderImpl() {
		this.reader = new ObjectMapper().readerFor(Map.class);
	}

	@Override
	public List<JwkImpl> readJwks(InputStream inputStream) throws IOException, InvalidSigningKeysException {
		@SuppressWarnings("unchecked")
		Map<String, Object> value = (Map<String, Object>)reader.readValue(inputStream);
		@SuppressWarnings("unchecked")
		final List<Map<String, Object>> keys = (List<Map<String, Object>>)value.get("keys");

		List<JwkImpl> jwks = new ArrayList<>();
		for (Map<String, Object> values : keys) {
			jwks.add(JwkImpl.fromValues(values));
		}
		return jwks;
	}

}
