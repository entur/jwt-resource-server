package org.entur.jwt.spring.config;

import org.entur.jwt.junit5.impl.DefaultAuthorizationServerEncoder;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

/**
 * Authorization server encoder whose RSA key (and so key id) is shared by all authorization servers using it,
 * i.e. their tokens have identical headers.
 */
public class SharedKeyAuthorizationServerEncoder extends DefaultAuthorizationServerEncoder {

    private static final KeyPair SHARED_KEY_PAIR = createSharedKeyPair();

    private static KeyPair createSharedKeyPair() {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048);
            return keyGen.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    protected KeyPair createKeyPair() {
        return SHARED_KEY_PAIR;
    }
}
