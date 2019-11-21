package org.entur.jwt.client;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public abstract class BaseAccessTokenProvider implements AccessTokenProvider {

	protected static final Logger logger = LoggerFactory.getLogger(BaseAccessTokenProvider.class);

    protected final AccessTokenProvider provider;

    public BaseAccessTokenProvider(AccessTokenProvider provider) {
        this.provider = provider;
    }
    
    public AccessTokenProvider getProvider() {
        return provider;
    }
    
    public AccessTokenHealth getHealth(boolean refresh) {
    	return provider.getHealth(refresh);
    }    
  
}
