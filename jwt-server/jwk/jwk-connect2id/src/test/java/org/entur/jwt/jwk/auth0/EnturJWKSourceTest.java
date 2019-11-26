package org.entur.jwt.jwk.auth0;


import static net.jadler.Jadler.closeJadler;
import static net.jadler.Jadler.initJadler;
import static net.jadler.Jadler.onRequest;
import static net.jadler.Jadler.port;

import java.io.FileNotFoundException;
import java.net.SocketTimeoutException;
import java.net.URL;
import java.nio.charset.Charset;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.TimeUnit;

import org.entur.jwt.jwk.connect2id.Connect2IdJwkProviderBuilder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

import com.nimbusds.jose.RemoteKeySourceException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import net.jadler.Request;
import net.jadler.stubbing.Responder;
import net.jadler.stubbing.StubResponse;

/**
 * Adapted from nimbus-jose-jwt RemoteJWKSetTest
 *
 */

public class EnturJWKSourceTest {

	@BeforeEach
	public void setUp() {
		initJadler();
	}

	@AfterEach
	public void tearDown() {
		closeJadler();
	}

	@Test
	public void testSimplifiedConstructor() throws Exception {

		KeyPairGenerator pairGen = KeyPairGenerator.getInstance("RSA");
		pairGen.initialize(1024);
		KeyPair keyPair = pairGen.generateKeyPair();

		RSAKey rsaJWK1 = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
				.privateKey((RSAPrivateKey) keyPair.getPrivate())
				.keyID("1")
				.build();

		keyPair = pairGen.generateKeyPair();

		RSAKey rsaJWK2 = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
				.privateKey((RSAPrivateKey) keyPair.getPrivate())
				.keyID("2")
				.build();

		JWKSet jwkSet = new JWKSet(Arrays.asList((JWK)rsaJWK1, (JWK)rsaJWK2));

		URL jwkSetURL = new URL("http://localhost:" + port() + "/jwks.json");

		onRequest()
		.havingMethodEqualTo("GET")
		.havingPathEqualTo("/jwks.json")
		.respond()
		.withStatus(200)
		.withHeader("Content-Type", "application/json")
		.withBody(jwkSet.toJSONObject(true).toJSONString());

		JWKSource<SecurityContext> jwkSetSource = Connect2IdJwkProviderBuilder.newBuilder(jwkSetURL).build();

		List<JWK> matches = jwkSetSource.get(new JWKSelector(new JWKMatcher.Builder().keyID("1").build()), null);

		RSAKey m1 = (RSAKey) matches.get(0);
		assertEquals(rsaJWK1.getPublicExponent(), m1.getPublicExponent());
		assertEquals(rsaJWK1.getModulus(), m1.getModulus());
		assertEquals("1", m1.getKeyID());

		assertEquals(1, matches.size());
	}

	@Test
	public void testSelectRSAByKeyID_defaultRetriever()
			throws Exception {

		KeyPairGenerator pairGen = KeyPairGenerator.getInstance("RSA");
		pairGen.initialize(1024);
		KeyPair keyPair = pairGen.generateKeyPair();

		RSAKey rsaJWK1 = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
				.privateKey((RSAPrivateKey) keyPair.getPrivate())
				.keyID("1")
				.build();

		keyPair = pairGen.generateKeyPair();

		RSAKey rsaJWK2 = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
				.privateKey((RSAPrivateKey) keyPair.getPrivate())
				.keyID("2")
				.build();

		JWKSet jwkSet = new JWKSet(Arrays.asList((JWK)rsaJWK1, (JWK)rsaJWK2));

		URL jwkSetURL = new URL("http://localhost:" + port() + "/jwks.json");

		onRequest()
		.havingMethodEqualTo("GET")
		.havingPathEqualTo("/jwks.json")
		.respond()
		.withStatus(200)
		.withHeader("Content-Type", "application/json")
		.withBody(jwkSet.toJSONObject(true).toJSONString());

		JWKSource<SecurityContext> jwkSetSource = Connect2IdJwkProviderBuilder.newBuilder(jwkSetURL).build();

		List<JWK> matches = jwkSetSource.get(new JWKSelector(new JWKMatcher.Builder().keyID("1").build()), null);

		RSAKey m1 = (RSAKey) matches.get(0);
		assertEquals(rsaJWK1.getPublicExponent(), m1.getPublicExponent());
		assertEquals(rsaJWK1.getModulus(), m1.getModulus());
		assertEquals("1", m1.getKeyID());

		assertEquals(1, matches.size());
	}


	@Test
	public void testRefreshRSAByKeyID_defaultRetriever()
			throws Exception {

		KeyPairGenerator pairGen = KeyPairGenerator.getInstance("RSA");
		pairGen.initialize(1024);
		KeyPair keyPair = pairGen.generateKeyPair();

		final RSAKey rsaJWK1 = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
				.privateKey((RSAPrivateKey) keyPair.getPrivate())
				.keyID("1")
				.build();

		keyPair = pairGen.generateKeyPair();

		final RSAKey rsaJWK2 = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
				.privateKey((RSAPrivateKey) keyPair.getPrivate())
				.keyID("2")
				.build();

		keyPair = pairGen.generateKeyPair();

		final RSAKey rsaJWK3 = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
				.privateKey((RSAPrivateKey) keyPair.getPrivate())
				.keyID("3")
				.build();

		URL jwkSetURL = new URL("http://localhost:" + port() + "/jwks.json");

		onRequest()
		.havingMethodEqualTo("GET")
		.havingPathEqualTo("/jwks.json")
		.respondUsing(new Responder() {
			private int count = 0;
			@Override
			public StubResponse nextResponse(Request request) {

				if (! request.getMethod().equalsIgnoreCase("GET")) {
					return StubResponse.builder().status(405).build();
				}

				if (count == 0) {
					++count;
					return StubResponse.builder()
							.status(200)
							.header("Content-Type", "application/json")
							.body(new JWKSet(Arrays.asList((JWK)rsaJWK1, (JWK)rsaJWK2)).toJSONObject().toJSONString(), Charset.forName("UTF-8"))
							.build();
				}

				// Add 3rd key
				return StubResponse.builder()
						.status(200)
						.header("Content-Type", "application/json")
						.body(new JWKSet(Arrays.asList((JWK)rsaJWK1, (JWK)rsaJWK2, (JWK)rsaJWK3)).toJSONObject().toJSONString(), Charset.forName("UTF-8"))
						.build();
			}
		});

		JWKSource<SecurityContext> jwkSetSource = Connect2IdJwkProviderBuilder.newBuilder(jwkSetURL).build();

		List<JWK> matches = jwkSetSource.get(new JWKSelector(new JWKMatcher.Builder().keyID("1").build()), null);

		RSAKey m1 = (RSAKey) matches.get(0);
		assertEquals(rsaJWK1.getPublicExponent(), m1.getPublicExponent());
		assertEquals(rsaJWK1.getModulus(), m1.getModulus());
		assertEquals("1", m1.getKeyID());

		assertEquals(1, matches.size());

		// Select 3rd key, expect refresh of JWK set
		matches = jwkSetSource.get(new JWKSelector(new JWKMatcher.Builder().keyID("3").build()), null);

		m1 = (RSAKey) matches.get(0);
		assertEquals(rsaJWK3.getPublicExponent(), m1.getPublicExponent());
		assertEquals(rsaJWK3.getModulus(), m1.getModulus());
		assertEquals("3", m1.getKeyID());

		assertEquals(1, matches.size());
	}

	@Test
	public void testInvalidJWKSetURL()
			throws Exception {

		KeyPairGenerator pairGen = KeyPairGenerator.getInstance("RSA");
		pairGen.initialize(1024);
		KeyPair keyPair = pairGen.generateKeyPair();

		RSAKey rsaJWK1 = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
				.privateKey((RSAPrivateKey) keyPair.getPrivate())
				.keyID("1")
				.build();

		keyPair = pairGen.generateKeyPair();

		RSAKey rsaJWK2 = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
				.privateKey((RSAPrivateKey) keyPair.getPrivate())
				.keyID("2")
				.build();

		JWKSet jwkSet = new JWKSet(Arrays.asList((JWK)rsaJWK1, (JWK)rsaJWK2));

		URL jwkSetURL = new URL("http://localhost:" + port() + "/invalid-path");

		onRequest()
		.havingMethodEqualTo("GET")
		.havingPathEqualTo("/jwks.json")
		.respond()
		.withStatus(200)
		.withHeader("Content-Type", "application/json")
		.withBody(jwkSet.toJSONObject(true).toJSONString());

		JWKSource<SecurityContext> jwkSetSource = Connect2IdJwkProviderBuilder.newBuilder(jwkSetURL).build();

		try {
			jwkSetSource.get(new JWKSelector(new JWKMatcher.Builder().keyID("1").build()), null);
		} catch (RemoteKeySourceException e) {
			Throwable cause = e.getCause().getCause();
			assertTrue(cause instanceof FileNotFoundException);
		}
	}


	@Test
	public void testTimeout()
			throws Exception {

		URL jwkSetURL = new URL("http://localhost:" + port() + "/jwks.json");

		onRequest().respond().withDelay(800, TimeUnit.MILLISECONDS);

		JWKSource<SecurityContext> jwkSetSource = Connect2IdJwkProviderBuilder.newBuilder(jwkSetURL, 100, 100).build();

		try {
			jwkSetSource.get(new JWKSelector(new JWKMatcher.Builder().build()), null);
			fail();
		} catch (RemoteKeySourceException e) {
			assertTrue(e.getCause().getCause() instanceof SocketTimeoutException);
		}
	}
}
