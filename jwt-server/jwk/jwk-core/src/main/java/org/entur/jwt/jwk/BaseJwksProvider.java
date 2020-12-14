package org.entur.jwt.jwk;

import java.io.IOException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public abstract class BaseJwksProvider<T> implements JwksProvider<T> {

    protected static final Logger logger = LoggerFactory.getLogger(BaseJwksProvider.class);

    protected final JwksProvider<T> provider;

    public BaseJwksProvider(JwksProvider<T> provider) {
        this.provider = provider;
    }

    public JwksProvider<T> getProvider() {
        return provider;
    }

    @Override
    public JwksHealth getHealth(boolean refresh) {
        return provider.getHealth(refresh);
    }
    
    @Override
    public void close() throws IOException {
        provider.close();
    }

}
