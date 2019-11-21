package org.entur.jwt.verifier;

import java.util.Map;
import java.util.Map.Entry;

import org.entur.jwt.jwk.JwksException;
import org.entur.jwt.jwk.JwksHealth;

public class JwtClaimVerifier<T> implements JwtVerifier<T> {

	private final JwtClaimExtractor<T> extractor;
	private final JwtVerifier<T> delegate;
	
	/** claim data-type validation */
    private final Map<String, Class<?>> types;
	/** claim value validation */
    private final Map<String, Object> values;

	public JwtClaimVerifier(JwtVerifier<T> delegate, JwtClaimExtractor<T> extractor, Map<String, Class<?>> types, Map<String, Object> values) {
		this.extractor = extractor;
		this.delegate = delegate;
		this.types = types;
		this.values = values;
	}

	@Override
	public T verify(String token) throws JwtException, JwksException {
		T validatedToken = delegate.verify(token);
		
		verifyClaimTypes(validatedToken);
		verifyClaimValues(validatedToken);
		
		return validatedToken;
	}

	protected void verifyClaimTypes(T token) throws JwtClaimException {
        for (Entry<String, Class<?>> entry : types.entrySet()) {
        	Object claim = extractor.getClaim(token, entry.getKey(), entry.getValue());
        	if(claim == null) {
                throw new JwtClaimException("Null or missing " + entry.getKey() + " claim.");
        	}
        	
        	Class<?> targetClass = entry.getValue();
        	Class<?> valueClass = claim.getClass();
        	
        	if(!targetClass.isAssignableFrom(valueClass)) {
        		// cross-check Long vs Integer, as some JSON parsers return one or the other
        		
            	if( (valueClass == Integer.class && targetClass == Long.class) || (valueClass == Long.class && targetClass == Integer.class)) {
            		// approved
            	} else {
            		throw new JwtClaimException("Unable to parse " + entry.getKey() + " claim value " + claim + " type " + claim.getClass().getName() + " as " + entry.getValue().getName());
            	}
        	}
		}		
	}
	
	protected void verifyClaimValues(T token) throws JwtClaimException {
        for (Entry<String, Object> entry : values.entrySet()) {
        	Object claim = extractor.getClaim(token, entry.getKey(), entry.getValue().getClass());
        	if(claim == null) {
                throw new JwtClaimException("Null or missing " + entry.getKey() + " claim.");
        	}

        	if(!entry.getValue().equals(claim)) {
        		if(!isEqual(entry.getValue(), claim)) {
        			throw new JwtClaimException("Expected claim " + entry.getKey() + " value " + entry.getValue() + ", found " + claim);
        		}
        	}
		}		
	}	

	private boolean isEqual(Object targetValue, Object claim) {
    	Class<?> targetClass = targetValue.getClass();
    	Class<?> valueClass = claim.getClass();

		if(valueClass == Integer.class && targetClass == Long.class) {
    		// ints can always become longs, so compare values
    		Integer integerValue = (Integer)claim;
    		Long longValue = (Long)targetValue;
    		
    		return integerValue.longValue() == longValue.longValue();
    	} else if(valueClass == Long.class && targetClass == Integer.class) {
    		Long longValue = (Long)claim;
			Integer integerValue = (Integer)targetValue;

    		if(longValue.longValue() <= Integer.MAX_VALUE && longValue.longValue() >= Integer.MIN_VALUE) {
    			return integerValue.longValue() == longValue.longValue();
    		}
    	}
		return false;
	}

	@Override
	public JwksHealth getHealth(boolean refresh) {
		return delegate.getHealth(refresh);
	}
}
