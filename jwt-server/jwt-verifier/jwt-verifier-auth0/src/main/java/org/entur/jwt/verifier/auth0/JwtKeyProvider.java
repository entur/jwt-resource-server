package org.entur.jwt.verifier.auth0;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import org.entur.jwt.jwk.JwkProvider;

import com.auth0.jwk.InvalidPublicKeyException;
import com.auth0.jwk.Jwk;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.RSAKeyProvider;
import org.entur.jwt.jwk.JwksException;

public class JwtKeyProvider implements RSAKeyProvider {

	private final JwkProvider<Jwk> provider;
	
    public JwtKeyProvider(JwkProvider<Jwk> provider) {
		super();
		this.provider = provider;
	}

	@Override
    public RSAPublicKey getPublicKeyById(String keyId) {
        try {
            return (RSAPublicKey) provider.getJwk(keyId).getPublicKey();
        } catch (org.entur.jwt.jwk.JwksUnavailableException e) {
        	throw new SigningKeyUnavailableException("Problem getting public key id " + keyId, e);
        } catch (JwksException | InvalidPublicKeyException e) {
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
