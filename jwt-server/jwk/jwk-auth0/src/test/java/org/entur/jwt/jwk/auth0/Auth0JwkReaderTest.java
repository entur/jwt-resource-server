package org.entur.jwt.jwk.auth0;

import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.Assert.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.codec.binary.Base64;
import org.entur.jwt.jwk.InvalidSigningKeysException;
import org.junit.jupiter.api.Test;

import com.auth0.jwk.InvalidPublicKeyException;
import com.auth0.jwk.Jwk;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.Lists;
import com.google.common.collect.Maps;

public class Auth0JwkReaderTest {

	private static final String RS_256 = "RS256";
	private static final String RSA = "RSA";
	private static final String SIG = "sig";
	private static final String THUMBPRINT = "THUMBPRINT";
	private static final String MODULUS = "vGChUGMTWZNfRsXxd-BtzC4RDYOMqtIhWHol--HNib5SgudWBg6rEcxvR6LWrx57N6vfo68wwT9_FHlZpaK6NXA_dWFW4f3NftfWLL7Bqy90sO4vijM6LMSE6rnl5VB9_Gsynk7_jyTgYWdTwKur0YRec93eha9oCEXmy7Ob1I2dJ8OQmv2GlvA7XZalMxAq4rFnXLzNQ7hCsHrUJP1p7_7SolWm9vTokkmckzSI_mAH2R27Z56DmI7jUkL9fLU-jz-fz4bkNg-mPz4R-kUmM_ld3-xvto79BtxJvOw5qqtLNnRjiDzoqRv-WrBdw5Vj8Pvrg1fwscfVWHlmq-1pFQ";
	private static final String EXPONENT = "AQAB";
	private static final String CERT_CHAIN = "CERT_CHAIN";
	private static final List<String> KEY_OPS_LIST = Lists.newArrayList("sign");
	private static final String KEY_OPS_STRING = "sign";
	private static final String CERT_URL = "https://localhost";

	private Auth0JwkReader reader = new Auth0JwkReader();

	@Test
	public void shouldBuildWithMap() throws Exception {
		final String kid = randomKeyId();
		Map<String, Object> values = publicKeyValues(kid, KEY_OPS_LIST);
		Jwk jwk = fromValues(values);

		assertThat(jwk.getId(), equalTo(kid));
		assertThat(jwk.getAlgorithm(), equalTo(RS_256));
		assertThat(jwk.getType(), equalTo(RSA));
		assertThat(jwk.getUsage(), equalTo(SIG));
		assertThat(jwk.getOperationsAsList(), equalTo(KEY_OPS_LIST));
		assertThat(jwk.getOperations(), is(KEY_OPS_STRING));
		assertThat(jwk.getCertificateThumbprint(), equalTo(THUMBPRINT));
		assertThat(jwk.getCertificateChain(), contains(CERT_CHAIN));
		assertThat(jwk.getCertificateUrl(), is(CERT_URL));
	}

	@Test
	public void shouldReturnPublicKey() throws Exception {
		final String kid = randomKeyId();
		Map<String, Object> values = publicKeyValues(kid, KEY_OPS_LIST);
		Jwk jwk = fromValues(values);

		assertThat(jwk.getPublicKey(), notNullValue());
		assertThat(jwk.getOperationsAsList(), is(KEY_OPS_LIST));
		assertThat(jwk.getOperations(), is(KEY_OPS_STRING));
	}

	@Test
	public void shouldReturnPublicKeyForStringKeyOpsParam() throws Exception {
		final String kid = randomKeyId();
		Map<String, Object> values = publicKeyValues(kid, KEY_OPS_STRING);
		Jwk jwk = fromValues(values);

		assertThat(jwk.getPublicKey(), notNullValue());
		assertThat(jwk.getOperationsAsList(), is(KEY_OPS_LIST));
		assertThat(jwk.getOperations(), is(KEY_OPS_STRING));
	}

	@Test
	public void shouldReturnPublicKeyForNullKeyOpsParam() throws Exception {
		final String kid = randomKeyId();
		Map<String, Object> values = publicKeyValues(kid, null);
		Jwk jwk = fromValues(values);

		assertThat(jwk.getPublicKey(), notNullValue());
		assertThat(jwk.getOperationsAsList(), nullValue());
		assertThat(jwk.getOperations(), nullValue());
	}

	@Test
	public void shouldReturnPublicKeyForEmptyKeyOpsParam() throws Exception {
		final String kid = randomKeyId();
		Map<String, Object> values = publicKeyValues(kid, Lists.newArrayList());
		Jwk jwk = fromValues(values);

		assertThat(jwk.getPublicKey(), notNullValue());
		assertThat(jwk.getOperationsAsList(), notNullValue());
		assertThat(jwk.getOperationsAsList().size(), equalTo(0));
		assertThat(jwk.getOperations(), nullValue());
	}

	@Test
	public void shouldThrowForNonRSAKey() throws Exception {
		final String kid = randomKeyId();
		Map<String, Object> values = nonRSAValues(kid);
		Jwk jwk = fromValues(values);

		assertThrows(InvalidPublicKeyException.class,
				()->{
					jwk.getPublicKey();
				} );           
	}

	@Test
	public void shouldNotThrowExceptionOnMissingKidParam() throws Exception {
		//kid is optional - https://tools.ietf.org/html/rfc7517#section-4.5
		final String kid = randomKeyId();
		Map<String, Object> values = publicKeyValues(kid, KEY_OPS_LIST);
		values.remove("kid");
		fromValues(values);
	}

	@Test
	public void shouldThrowInvalidSigningKeysExceptionOnMissingKtyParam() throws Exception {
		final String kid = randomKeyId();
		Map<String, Object> values = publicKeyValues(kid, KEY_OPS_LIST);
		values.remove("kty");

		assertThrows(InvalidSigningKeysException.class,
				()->{
					fromValues(values);
				} ); 
	}

	@Test
	public void shouldReturnKeyWithMissingAlgParam() throws Exception {
		final String kid = randomKeyId();
		Map<String, Object> values = publicKeyValues(kid, KEY_OPS_LIST);
		values.remove("alg");
		Jwk jwk = fromValues(values);
		assertThat(jwk.getPublicKey(), notNullValue());
	}

	@Test
	public void shouldKeepAdditionalAttributes() throws Exception {
		final String kid = randomKeyId();
		Map<String, Object> values = publicKeyValues(kid, KEY_OPS_LIST);
		values.put("additional", "attribute");
		Jwk jwk = fromValues(values);

		assertThat(jwk.getAdditionalAttributes().get("additional"), is("attribute"));
	}

	@Test
	public void shouldReturnToString() throws Exception {
		final String kid = randomKeyId();
		Map<String, Object> values = publicKeyValues(kid, KEY_OPS_LIST);
		Jwk jwk = fromValues(values);

		String toString = jwk.toString();

		assertThat(toString, containsString(kid));
	}    

	private static String randomKeyId() {
		byte[] bytes = new byte[50];
		new SecureRandom().nextBytes(bytes);
		return Base64.encodeBase64String(bytes);
	}

	private static Map<String, Object> nonRSAValues(String kid) {
		Map<String, Object> values = Maps.newHashMap();
		values.put("alg", "AES_256");
		values.put("kty", "AES");
		values.put("use", SIG);
		values.put("kid", kid);
		return values;
	}

	private static Map<String, Object> publicKeyValues(String kid, Object keyOps) {
		Map<String, Object> values = Maps.newHashMap();
		values.put("alg", RS_256);
		values.put("kty", RSA);
		values.put("use", SIG);
		values.put("key_ops", keyOps);
		values.put("x5c", Lists.newArrayList(CERT_CHAIN));
		values.put("x5t", THUMBPRINT);
		values.put("x5u", CERT_URL);
		values.put("kid", kid);
		values.put("n", MODULUS);
		values.put("e", EXPONENT);
		return values;
	}
	
	private Jwk fromValues(Map<String, Object> values) throws Exception {
		Map<String, Object> jwks = new HashMap<>();

		List<Object> keys = Arrays.asList(values);

		jwks.put("keys", keys);

		ObjectMapper mapper = new ObjectMapper();
		String json = mapper.writeValueAsString(jwks);
		
		List<Jwk> deserialized = reader.readJwks(json.getBytes(StandardCharsets.UTF_8));
		return deserialized.get(0);
	}	
}
