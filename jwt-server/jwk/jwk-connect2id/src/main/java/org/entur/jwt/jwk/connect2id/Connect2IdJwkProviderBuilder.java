package org.entur.jwt.jwk.connect2id;

import java.net.URL;

import org.entur.jwt.jwk.JwksProvider;
import org.entur.jwt.jwk.UrlJwksProvider;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.proc.SecurityContext;

public class Connect2IdJwkProviderBuilder<C extends SecurityContext> extends AbstractJWKSourceBuilder<C, Connect2IdJwkProviderBuilder<C>> {

	public static <C extends SecurityContext> Connect2IdJwkProviderBuilder<C> newBuilder(URL url) {
		UrlJwksProvider<JWK> jwksProvider = new UrlJwksProvider<>(url, new Connect2IdJwkReader());
		return new Connect2IdJwkProviderBuilder<>(jwksProvider);
	}

	public static <C extends SecurityContext> Connect2IdJwkProviderBuilder<C> newBuilder(URL url, Integer connectTimeout, Integer readTimeout) {
		UrlJwksProvider<JWK> jwksProvider = new UrlJwksProvider<>(url, new Connect2IdJwkReader(), connectTimeout, readTimeout);
		return new Connect2IdJwkProviderBuilder<>(jwksProvider);
	}

	public Connect2IdJwkProviderBuilder(JwksProvider<JWK> jwksProvider) {
		super(jwksProvider);
	}

}
