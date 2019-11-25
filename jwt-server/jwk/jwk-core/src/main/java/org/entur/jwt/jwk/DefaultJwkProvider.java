package org.entur.jwt.jwk;

import java.util.List;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;

import org.entur.jwt.jwk.AbstractCachedJwksProvider.JwkListCacheItem;

/**
 * Jwk provider extracts a key from an underlying {@linkplain JwksProvider}.
 */

public class DefaultJwkProvider<T> extends BaseJwksProvider<T> implements JwkProvider<T> {

    private final JwkFieldExtractor<T> fieldExtractor;
    /**
     * Creates a new provider.
     *
     * @param provider source of jwks.
     * @param fieldExtractor field extractor
     */
    public DefaultJwkProvider(final JwksProvider<T> provider, JwkFieldExtractor<T> fieldExtractor) {
    	super(provider);
        this.fieldExtractor = fieldExtractor;
    }

    @Override
    public T getJwk(final String keyId) throws JwksException {
    	List<T> jwks = provider.getJwks(false);
    	T jwk = getJwk(keyId, jwks);
    	if(jwk == null) {
    		// refresh if unknown key
    		jwks = provider.getJwks(true);
    		jwk = getJwk(keyId, jwks);
    	}
		if(jwk != null) {
			return jwk;
		}
		
		throw createException(keyId, jwks);
    }

	private JwkNotFoundException createException(final String keyId, List<T> jwks ) {
		StringBuilder builder = new StringBuilder();
		for(T t: jwks) {
			builder.append(fieldExtractor.getJwkId(t));
			builder.append(", ");
		}
		if(builder.length() > 0) {
			builder.setLength(builder.length() - 2);
		}
        return new JwkNotFoundException("No key found for key id " + keyId + ", only have " + builder);
	}
    
    protected T getJwk(String keyId, List<T> jwks) {
        for (T jwk : jwks) {
            if (Objects.equals(keyId, fieldExtractor.getJwkId(jwk))) {
                return jwk;
            }
        } 
        return null;
    }

	@Override
	public List<T> getJwks(boolean forceUpdate) throws JwksException {
		return provider.getJwks(forceUpdate);
	}

	@Override
	public CompletionStage<T> getFutureJwk(String keyId) {
		// https://stackoverflow.com/questions/36307422/java-multi-nested-completionstage-equivalent-to-flatmap
    	CompletionStage<T> stage = provider.getFutureJwks(false).thenCompose( current -> {
    		T existingJwk = getJwk(keyId, current);
        	if(existingJwk == null) {
        		// refresh if unknown key
        		return provider.getFutureJwks(true).thenCompose( refreshed -> {
        			T refreshedJwk = getJwk(keyId, refreshed);
        			if(refreshedJwk == null) {
        				return CompletableFuture.failedFuture(createException(keyId, refreshed));
        			}
        			return CompletableFuture.completedStage(refreshedJwk);
        		});
        	}
   			return CompletableFuture.completedStage(existingJwk);
    	});
    	
    	return stage;
	}

}
