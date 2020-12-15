package org.entur.jwt.verifier.auth0;

import java.io.Closeable;

import com.auth0.jwt.interfaces.JWTVerifier;

/**
 * Helper interface to pass along closable. 
 * 
 */

public interface CloseableJWTVerifier extends JWTVerifier, Closeable {

}
