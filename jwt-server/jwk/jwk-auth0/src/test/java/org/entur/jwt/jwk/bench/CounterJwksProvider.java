package org.entur.jwt.jwk.bench;

import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import org.entur.jwt.jwk.JwksException;
import org.entur.jwt.jwk.JwksProvider;

public class CounterJwksProvider<T> implements JwksProvider<T> {

    private AtomicInteger counter = new AtomicInteger();
    
    private JwksProvider<T> delegate;
    
    public CounterJwksProvider(JwksProvider<T> delegate) {
        super();
        this.delegate = delegate;
    }

    @Override
    public List<T> getJwks(boolean forceUpdate) throws JwksException {
        counter.incrementAndGet();
        return delegate.getJwks(forceUpdate);
    }
    
    public int getCount() {
        return counter.get();
    }

}
