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
				if(!isIntegerType(targetClass) || !isIntegerType(valueClass)) {
					throw new JwtClaimException("Unable to parse " + entry.getKey() + " claim value " + claim + " type " + claim.getClass().getName() + " as " + entry.getValue().getName());
				}
			}
			
			// TODO also support list types, i.e. list of Strings and so on.
		}		
	}

	protected void verifyClaimValues(T token) throws JwtClaimException {
		for (Entry<String, Object> entry : values.entrySet()) {
			Object claim = extractor.getClaim(token, entry.getKey(), entry.getValue().getClass());
			if(claim == null) {
				throw new JwtClaimException("Null or missing " + entry.getKey() + " claim.");
			}

			if(!entry.getValue().equals(claim) && !isEqual(entry.getValue(), claim)) {
				throw new JwtClaimException("Expected claim " + entry.getKey() + " value " + entry.getValue() + ", found " + claim);
			}
		}		
	}	

	private boolean isEqual(Object targetValue, Object claim) {
		Class<?> targetClass = targetValue.getClass();
		Class<?> valueClass = claim.getClass();

		if(isIntegerType(targetClass) && isIntegerType(valueClass)) {
			return ((Number)targetValue).longValue() == ((Number)claim).longValue();
		}
		return false;
	}
	
	private boolean isIntegerType(Class<?> c) {
		return c == Long.class || c == Integer.class || c == Short.class || c == Short.class || c == Byte.class;
	}

	@Override
	public JwksHealth getHealth(boolean refresh) {
		return delegate.getHealth(refresh);
	}
}
