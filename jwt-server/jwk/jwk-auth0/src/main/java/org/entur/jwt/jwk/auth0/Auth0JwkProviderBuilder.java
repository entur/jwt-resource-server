package org.entur.jwt.jwk.auth0;

import java.net.URL;

import org.entur.jwt.jwk.JwkProviderBuilder;
import org.entur.jwt.jwk.JwksProvider;
import org.entur.jwt.jwk.UrlJwksProvider;

import com.auth0.jwk.Jwk;

public class Auth0JwkProviderBuilder extends JwkProviderBuilder<Jwk> {

    public static JwkProviderBuilder<Jwk> newBuilder(URL url) {
        UrlJwksProvider<Jwk> jwksProvider = new UrlJwksProvider<>(url, new Auth0JwkReader());
        return new Auth0JwkProviderBuilder(jwksProvider);
    }

    public static JwkProviderBuilder<Jwk> newBuilder(URL url, Integer connectTimeout, Integer readTimeout) {
        UrlJwksProvider<Jwk> jwksProvider = new UrlJwksProvider<>(url, new Auth0JwkReader(), connectTimeout, readTimeout);
        return new Auth0JwkProviderBuilder(jwksProvider);
    }

    public Auth0JwkProviderBuilder(JwksProvider<Jwk> jwksProvider) {
        super(jwksProvider, new Auth0JwkFieldExtractor());
    }

}
