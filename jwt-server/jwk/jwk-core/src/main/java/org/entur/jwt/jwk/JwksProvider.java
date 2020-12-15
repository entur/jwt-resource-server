package org.entur.jwt.jwk;

import java.io.Closeable;
import java.util.List;

/**
 * Provider of a list of Jwk.
 */
public interface JwksProvider<T> extends JwksHealthProvider, Closeable {

    /**
     * Returns a list of Jwk.
     * 
     * @param forceUpdate if true, bypass existing caches and get new values
     * 
     * @return a list of Jwk
     * @throws JwksException if no list can be retrieved
     */
    List<T> getJwks(boolean forceUpdate) throws JwksException;

}
