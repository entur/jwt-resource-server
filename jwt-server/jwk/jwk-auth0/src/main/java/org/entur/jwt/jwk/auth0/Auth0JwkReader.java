package org.entur.jwt.jwk.auth0;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.entur.jwt.jwk.InvalidSigningKeysException;
import org.entur.jwt.jwk.JwksReader;

import com.auth0.jwk.Jwk;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.databind.MappingJsonFactory;

public class Auth0JwkReader implements JwksReader<Jwk> {

	private final MappingJsonFactory factory = new MappingJsonFactory();

	@Override
	public List<Jwk> readJwks(InputStream inputStream) throws IOException, InvalidSigningKeysException {
		JsonParser parser = factory.createParser(inputStream);

		try {
			JsonToken nextToken = parser.nextToken();
			if(nextToken != JsonToken.START_OBJECT) {
				throw new InvalidSigningKeysException("Unexpected type " + nextToken.name());
			}

			do {
				nextToken = parser.nextToken();
				if(nextToken == null) {
					break;
				}

				if(nextToken == JsonToken.FIELD_NAME) {
					if(parser.getCurrentName().equals("keys")) {
						nextToken = parser.nextToken();
						if(nextToken == JsonToken.START_ARRAY) {
							return parseJwks(parser);
						} else {
							throw new InvalidSigningKeysException("Unexpected type " + nextToken.name());
						}
					}
				} else if(nextToken.isStructStart()) {
					parser.skipChildren();
				}
			} while(true);
		} finally {
			parser.close();
		}

		throw new InvalidSigningKeysException("No keys field found");
	}

	@SuppressWarnings("unchecked")
	private List<Jwk> parseJwks(JsonParser parser) throws IOException, InvalidSigningKeysException {
		List<Map<String, Object>> values = parser.readValueAs(List.class);

		List<Jwk> jwks = new ArrayList<>(values.size());

		for (Map<String, Object> value : values) {
			jwks.add(fromValues(value));
		}

		return jwks;
	}

	public static Jwk fromValues(Map<String, Object> map) throws InvalidSigningKeysException {
		try {
			return Jwk.fromValues(map);
		} catch(IllegalArgumentException e) {
			throw new InvalidSigningKeysException("Attributes " + map + " are not from a valid jwk", e);
		}
	}

}
