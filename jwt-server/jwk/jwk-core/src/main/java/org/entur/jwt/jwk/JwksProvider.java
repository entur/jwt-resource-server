package org.entur.jwt.jwk;

import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;

/**
 * Provider of a list of Jwk.
 */
public interface JwksProvider<T> extends JwksHealthProvider {
    
    /**
     * Returns a list of Jwk.
     * @param forceUpdate if true, bypass existing caches and get new values 
     * 
     * @return a list of Jwk
     * @throws JwksException if no list can be retrieved
     */
    List<T> getJwks(boolean forceUpdate) throws JwksException;
    
    // https://www.deadcoderising.com/java8-writing-asynchronous-code-with-completablefuture/
    // https://www.baeldung.com/spring-webflux
    // https://www.baeldung.com/spring-security-5-reactive
    CompletionStage<List<T>> getFutureJwks(boolean forceUpdate);
}
