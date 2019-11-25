package org.entur.jwt.jwk;

import java.util.List;
import java.util.concurrent.CompletionStage;

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
    
    public JwksHealth getHealth(boolean refresh) {
    	return provider.getHealth(refresh);
    }
    
	@Override
	public CompletionStage<List<T>> getFutureJwks(boolean forceUpdate) {
		return provider.getFutureJwks(forceUpdate);
	}    
}
