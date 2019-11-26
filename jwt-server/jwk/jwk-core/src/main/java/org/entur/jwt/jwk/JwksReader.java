package org.entur.jwt.jwk;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.List;

public interface JwksReader<T> {

	List<T> readJwks(InputStream json) throws IOException, InvalidSigningKeysException;

	default List<T> readJwks(byte[] json) throws IOException, InvalidSigningKeysException {
		return readJwks(new ByteArrayInputStream(json));
	}
}
