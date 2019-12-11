package org.entur.jwt.junit5.impl;

import java.net.URL;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import com.auth0.jwk.JwkException;
import com.auth0.jwk.JwkProvider;
import com.auth0.jwk.UrlJwkProvider;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.RSAKeyProvider;

/**
 * Class for Fetching public key for verification of JWT token.
 *
 * Thread safe.
 */
public class KeyProvider implements RSAKeyProvider {

    private final JwkProvider provider;

    public KeyProvider(URL url) {
        provider = new UrlJwkProvider(url);
    }

    @Override
    public RSAPublicKey getPublicKeyById(String keyId) {
        try {
            return (RSAPublicKey) provider.get(keyId).getPublicKey();
        } catch (JwkException e) {
            throw new JWTVerificationException("Problem getting public key id " + keyId, e);
        }
    }

    @Override
    public RSAPrivateKey getPrivateKey() {
        throw new RuntimeException("Attempted to acquire private key from authentication service.");
    }

    @Override
    public String getPrivateKeyId() {
        throw new RuntimeException("Attempted to acquire private key id from authentication service.");
    }
}
