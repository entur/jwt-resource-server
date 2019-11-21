package org.entur.jwt.junit5.impl;

import java.lang.annotation.Annotation;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.entur.jwt.junit5.AccessToken;
import org.entur.jwt.junit5.AccessTokenEncoder;
import org.entur.jwt.junit5.AuthorizationServerEncoder;
import org.entur.jwt.junit5.claim.Audience;
import org.entur.jwt.junit5.claim.AuthorizedParty;
import org.entur.jwt.junit5.claim.BooleanArrayClaim;
import org.entur.jwt.junit5.claim.BooleanClaim;
import org.entur.jwt.junit5.claim.DoubleArrayClaim;
import org.entur.jwt.junit5.claim.DoubleClaim;
import org.entur.jwt.junit5.claim.ExpiresAt;
import org.entur.jwt.junit5.claim.IntegerArrayClaim;
import org.entur.jwt.junit5.claim.IssuedAt;
import org.entur.jwt.junit5.claim.Issuer;
import org.entur.jwt.junit5.claim.JsonClaim;
import org.entur.jwt.junit5.claim.IntegerClaim;
import org.entur.jwt.junit5.claim.Scope;
import org.entur.jwt.junit5.claim.StringArrayClaim;
import org.entur.jwt.junit5.claim.StringClaim;
import org.entur.jwt.junit5.claim.Subject;
import org.entur.jwt.junit5.claim.MapClaim;
import org.entur.jwt.junit5.claim.MapClaim.Entry;
import org.entur.jwt.junit5.configuration.resolve.ResourceServerConfiguration;
import org.entur.jwt.junit5.headers.AlgorithmHeader;
import org.entur.jwt.junit5.headers.KeyIdHeader;
import org.entur.jwt.junit5.headers.TypeHeader;
import org.entur.jwt.junit5.sabotage.Signature;

import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.api.extension.ParameterContext;

import com.fasterxml.jackson.databind.util.RawValue;

public class DefaultAccessTokenEncoder implements AccessTokenEncoder {

	private final static Class<? extends Annotation>[] fixedClaims = new Class[] {
		Audience.class,
		AuthorizedParty.class,
		ExpiresAt.class,
		IssuedAt.class,
		Issuer.class,
		Scope.class,
		Subject.class		
	};
	
	private final static Class<? extends Annotation>[] customClaims = new Class[]{
			MapClaim.class,
			BooleanClaim.class,
			IntegerClaim.class,
			StringClaim.class,
			DoubleClaim.class,
			BooleanArrayClaim.class,
			IntegerArrayClaim.class,
			StringArrayClaim.class,
			DoubleArrayClaim.class,
			JsonClaim.class
	};
	
	private final static Class<? extends Annotation>[] fixedSabotages = new Class[] {
			Signature.class,
		};
	
	private final static Class<? extends Annotation>[] fixedHeaders = new Class[] {
			AlgorithmHeader.class,
			KeyIdHeader.class,
			TypeHeader.class
		};	
	
	@Override
	public String encode(ParameterContext parameterContext, ExtensionContext extensionContext, Annotation authorizationServer, AuthorizationServerEncoder encoder, ResourceServerConfiguration resolver) {
		String token = encoder.getToken(authorizationServer, encodeClaims(parameterContext, resolver), encoderHeaders(parameterContext, resolver));
		
		return sabotageToken(token, parameterContext, resolver);
	}
	
	protected String sabotageToken(String token, ParameterContext parameterContext, ResourceServerConfiguration resolver) {
		return encodeKnownSabotages(token, parameterContext);
	}

	protected String encodeKnownSabotages(String token, ParameterContext parameterContext) {
		List<Object> parameters = extractKnownSabotages(parameterContext);

		for(Object c : parameters) {
			if(c instanceof Signature) {
				Signature s = (Signature)c;
				
				int index = token.lastIndexOf('.');
				
				token = token.substring(index + 1) + s.value();
			} else {
				throw new IllegalArgumentException("Unsupported sabotage type " + c);
			}
		}
		return token;
	}

	public Map<String, Object> encoderHeaders(ParameterContext parameterContext, ResourceServerConfiguration resolver) {
		Map<String, Object> result = new HashMap<>();

		encodeKnownHeaders(parameterContext, result, resolver);

		return result;
	}
	
	protected void encodeKnownHeaders(ParameterContext parameterContext, Map<String, Object> result, ResourceServerConfiguration resolver) {
		List<Object> parameters = extractKnownHeaders(parameterContext);
		for(Object c : parameters) {
			if(c instanceof AlgorithmHeader) {
				AlgorithmHeader b = (AlgorithmHeader)c;
				result.put("alg", b.value());
			} else if(c instanceof KeyIdHeader) {
				KeyIdHeader b = (KeyIdHeader)c;
				result.put("kid", b.value());
			} else if(c instanceof TypeHeader) {
				TypeHeader b = (TypeHeader)c;
				result.put("typ", b.value());
			} else {
				throw new IllegalArgumentException("Unsupported header type " + c);
			}
		}
	}

	public Map<String, Object> encodeClaims(ParameterContext parameterContext, ResourceServerConfiguration resolver) {
		Map<String, Object> result = new HashMap<>();

		Optional<AccessToken> a = parameterContext.findAnnotation(AccessToken.class);
		if(a.isPresent()) {
			encode(result, a.get(), resolver);			
		}

		encodeKnownClaims(parameterContext, result, resolver);
		encodeCustomClaims(parameterContext, result, resolver);
		
		transformParameters(result);
		
		return result;
	}

	protected void transformParameters(Map<String, Object> result) {
		Long issuedAt = (Long)result.get("iat");
		result.put("iat",  System.currentTimeMillis() / 1000 + issuedAt);
		
		Long expiresAt = (Long)result.get("exp");
		result.put("exp", System.currentTimeMillis() / 1000 + expiresAt);
	}

	protected void encodeKnownClaims(ParameterContext parameterContext, Map<String, Object> result, ResourceServerConfiguration resolver) {
		List<Object> parameters = extractKnownClaims(parameterContext);
		if(!parameters.isEmpty()) {
			for(Object c : parameters) {
				if(c instanceof Audience) {
					Audience b = (Audience)c;
					result.put("aud", b.value());
				} else if(c instanceof AuthorizedParty) {
					AuthorizedParty b = (AuthorizedParty)c;
					result.put("azp", b.value());
				} else if(c instanceof ExpiresAt) {
					ExpiresAt b = (ExpiresAt)c;
					result.put("exp", b.value());
				} else if(c instanceof IssuedAt) {
					IssuedAt b = (IssuedAt)c;
					result.put("iat", b.value());
				} else if(c instanceof Issuer) {
					Issuer b = (Issuer)c;
					result.put("iss", b.value());
				} else if(c instanceof Scope) {
					Scope b = (Scope)c;
					result.put("scope", String.join(" ", b.value()));
				} else if(c instanceof Subject) {
					Subject b = (Subject)c;
					result.put("sub", b.value());
				} else {
					throw new IllegalArgumentException("Unsupported claim type " + c);
				}
			}
		}
	}	
	
	protected void encodeCustomClaims(ParameterContext parameterContext, Map<String, Object> result, ResourceServerConfiguration resolver) {
		List<Object> parameters = extractCustomClaims(parameterContext);
		if(!parameters.isEmpty()) {
			for(Object c : parameters) {
				if(c instanceof BooleanClaim) {
					BooleanClaim b = (BooleanClaim)c;
					result.put(b.name(), b.value());
				} else if(c instanceof IntegerClaim) {
					IntegerClaim b = (IntegerClaim)c;
					result.put(b.name(), b.value());
				} else if(c instanceof DoubleClaim) {
					DoubleClaim b = (DoubleClaim)c;
					result.put(b.name(), b.value());
				} else if(c instanceof StringClaim) {
					StringClaim b = (StringClaim)c;
					result.put(b.name(), b.value());
				} else if(c instanceof BooleanArrayClaim) {
					BooleanArrayClaim b = (BooleanArrayClaim)c;
					result.put(b.name(), b.value());
				} else if(c instanceof IntegerClaim) {
					IntegerArrayClaim b = (IntegerArrayClaim)c;
					result.put(b.name(), b.value());
				} else if(c instanceof DoubleArrayClaim) {
					DoubleArrayClaim b = (DoubleArrayClaim)c;
					result.put(b.name(), b.value());
				} else if(c instanceof StringArrayClaim) {
					StringArrayClaim b = (StringArrayClaim)c;
					result.put(b.name(), b.value());
				} else if(c instanceof MapClaim) {
					MapClaim mapClaim = (MapClaim)c;
					
					String[] paths = mapClaim.path();
					
					Map<String, Object> mapForPath = result;
					int i = 0;
					do {
						Map<String, Object> nextMapForPath = (Map<String, Object>) mapForPath.get(paths[i]);
						if(nextMapForPath == null) {
							nextMapForPath = new HashMap<>();
							mapForPath.put(paths[i], nextMapForPath);
						}
						mapForPath = nextMapForPath;
						
						i++;
					} while(i < paths.length);

					// start adding entries
					for (Entry entry : mapClaim.entries()) {
						String[] value = entry.value();
						
						if(!entry.alwaysArray() && value.length == 1) {
							mapForPath.put(entry.name(), valueForType(value[0], entry.type()));
						} else {
							// use a list, not an array, as its serialized the same as an array
							List<Object> list = new ArrayList<>();
							
							for(String v : value) {
								list.add(valueForType(v, entry.type()));
							}
							
							mapForPath.put(entry.name(), list);
						}
					}
				} else if(c instanceof JsonClaim) {
					JsonClaim jsonClaim = (JsonClaim)c;
					
					result.put(jsonClaim.name(), new RawValue(jsonClaim.value()));
				} else {
					throw new IllegalArgumentException("Unsupported claim type " + c);
				}
			}
		}
	}
	
	protected Object valueForType(String value, Class<?> type) {
		if(type == String.class) {
			return value;
		} else if(type == Long.class) {
			return Long.parseLong(value);
		} else if(type == Integer.class) {
			return Integer.parseInt(value);
		} else if(type == Boolean.class) {
			return Boolean.parseBoolean(value);
		} else if(type == Double.class) {
			return Double.parseDouble(value);
		} else if(type == Float.class) {
			return Float.parseFloat(value);
		}
		
		throw new IllegalArgumentException("Cant convert '" + value + "' to " + type.getName());
	}

	protected List<Object> extractCustomClaims(ParameterContext parameterContext) {
		List<Object> parameters = new ArrayList<>();
		for(Class<? extends Annotation> c : customClaims) {
			parameters.addAll(parameterContext.findRepeatableAnnotations(c));
		}
		return parameters;
	}
	
	protected List<Object> extractAnnotations(ParameterContext parameterContext, Class<? extends Annotation>[] items) {
		List<Object> parameters = new ArrayList<>(items.length);
		
		for(Class<? extends Annotation> c : items) {
			Optional<?> optional = parameterContext.findAnnotation(c);
			if(optional.isPresent()) {
				parameters.add(optional.get());
			}
		}
		return parameters;
		
	}
	
	protected List<Object> extractKnownClaims(ParameterContext parameterContext) {
		return extractAnnotations(parameterContext, fixedClaims);
	}
	
	protected List<Object> extractKnownHeaders(ParameterContext parameterContext) {
		return extractAnnotations(parameterContext, fixedHeaders);
	}	

	protected List<Object> extractKnownSabotages(ParameterContext parameterContext) {
		return extractAnnotations(parameterContext, fixedSabotages);
	}	
	
	protected void encode(Map<String, Object> result, AccessToken token, ResourceServerConfiguration resolver) {
		if(!result.containsKey("iss")) {
			result.put("iss", resolver.getProperty(token.by(), "issuer"));
		}
		if(!isBlank(token.subject())) {
			result.put("sub", token.subject());
		}

		if(!result.containsKey("aud")) {
			String[] audience = token.audience();
			if(audience != null && audience.length > 0) {
				result.put("aud", audience);
			} else {
				// TODO resolve from configuration?
			}
		}

		if(!result.containsKey("iat")) {
			result.put("iat", token.issuedAt() * 1000);
		}
		if(!result.containsKey("exp")) {
			result.put("exp", token.expiresAt() * 1000);
		}

		if(!result.containsKey("scope")) {
			if(!isBlank(token.scope())) {
				result.put("scope", token.scope());
			}
		}

		if(!result.containsKey("azp")) {
			if(!isBlank(token.authorizedParty())) {
				result.put("azp", token.authorizedParty());
			}
		}
		
		
	}
	
	private boolean isBlank(String[] scope) {
		return scope == null || scope.length == 0;
	}

	private boolean isBlank(String subject) {
		return subject == null || subject.isEmpty();
	}	
}
