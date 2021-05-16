package org.entur.jwt.jwk;

import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Simple provider for additional timeout protection. Creates a new thread pool for each invocation. 
 * For external HTTP calls, a better approach to implement a 'cancellable' approach, so 
 * that resources can be freed up.
 *
 * @param <T> list of JWKs
 */

public class TimeoutJwksProvider<T> extends BaseJwksProvider<T> {

    protected static final Logger logger = LoggerFactory.getLogger(TimeoutJwksProvider.class);

    private final long duration;
    
    public TimeoutJwksProvider(JwksProvider<T> provider, long duration) {
        super(provider);
        
        this.duration = duration;
    }

    @Override
    public List<T> getJwks(boolean forceUpdate) throws JwksException {
        Callable<List<T>> task = () -> provider.getJwks(forceUpdate);
        
        ExecutorService executor = Executors.newFixedThreadPool(1);
        
        Future<List<T>> future = executor.submit(task);
        
        try {
           return future.get(duration, TimeUnit.MILLISECONDS);
        } catch (ExecutionException ex) {
           Throwable cause = ex.getCause();
           if(cause instanceof JwksException) {
               throw (JwksException)cause;
           } else {
               throw new JwksUnavailableException(cause);
           }
        } catch (Exception e) {
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            throw new JwksUnavailableException(e);
        }
    }

}
