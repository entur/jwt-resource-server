package org.entur.jwt.spring;

import java.io.IOException;

import javax.annotation.PreDestroy;

import org.entur.jwt.jwk.JwksException;
import org.entur.jwt.jwk.JwksHealth;
import org.entur.jwt.verifier.JwtException;
import org.entur.jwt.verifier.JwtVerifier;

/**
 * Wrapper with pre-destroy call to {@linkplain #close()}.
 * 
 * @param <T> verified token type
 */

public class SpringJwtVerifier<T> implements JwtVerifier<T> {

    private final JwtVerifier<T> delegate;
    
    public SpringJwtVerifier(JwtVerifier<T> delegate) {
        this.delegate = delegate;
    }

    @PreDestroy
    public void cancelBackgroundRefreshes() {
        try {
            delegate.close();
        } catch (IOException e) {
            // ignore
        }
    }
    
    @Override
    public JwksHealth getHealth(boolean refresh) {
        return delegate.getHealth(refresh);
    }

    @Override
    public void close() throws IOException {
        delegate.close();
    }

    @Override
    public T verify(String token) throws JwtException, JwksException {
        return delegate.verify(token);
    }
}
