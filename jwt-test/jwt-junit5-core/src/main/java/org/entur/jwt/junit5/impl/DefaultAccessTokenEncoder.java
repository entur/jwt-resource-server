package org.entur.jwt.junit5.impl;

import com.fasterxml.jackson.databind.util.RawValue;
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
import org.entur.jwt.junit5.claim.IntegerClaim;
import org.entur.jwt.junit5.claim.IssuedAt;
import org.entur.jwt.junit5.claim.Issuer;
import org.entur.jwt.junit5.claim.JsonClaim;
import org.entur.jwt.junit5.claim.MapClaim;
import org.entur.jwt.junit5.claim.MapClaim.Entry;
import org.entur.jwt.junit5.claim.MissingClaim;
import org.entur.jwt.junit5.claim.NullClaim;
import org.entur.jwt.junit5.claim.Scope;
import org.entur.jwt.junit5.claim.StringArrayClaim;
import org.entur.jwt.junit5.claim.StringClaim;
import org.entur.jwt.junit5.claim.Subject;
import org.entur.jwt.junit5.configuration.resolve.ResourceServerConfiguration;
import org.entur.jwt.junit5.headers.AlgorithmHeader;
import org.entur.jwt.junit5.headers.KeyIdHeader;
import org.entur.jwt.junit5.headers.TypeHeader;
import org.entur.jwt.junit5.sabotage.Signature;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.api.extension.ParameterContext;

import java.lang.annotation.Annotation;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

public class DefaultAccessTokenEncoder implements AccessTokenEncoder {

    // header claims
    protected static final String TYP = "typ";
    protected static final String KID = "kid";
    protected static final String ALG = "alg";

    // payload claims
    protected static final String ISS = "iss";
    protected static final String SUB = "sub";
    protected static final String AUD = "aud";
    protected static final String IAT = "iat";
    protected static final String EXP = "exp";
    protected static final String AZP = "azp";
    protected static final String SCOPE = "scope";

    @SuppressWarnings("unchecked")
    private static final Class<? extends Annotation>[] fixedClaims = new Class[] { Audience.class, AuthorizedParty.class, ExpiresAt.class, IssuedAt.class, Issuer.class, Scope.class, Subject.class };

    @SuppressWarnings("unchecked")
    private static final Class<? extends Annotation>[] customClaims = new Class[] { MapClaim.class, BooleanClaim.class, IntegerClaim.class, StringClaim.class, DoubleClaim.class, BooleanArrayClaim.class, IntegerArrayClaim.class,
            StringArrayClaim.class, DoubleArrayClaim.class, JsonClaim.class, NullClaim.class, MissingClaim.class};

    @SuppressWarnings("unchecked")
    private static final Class<? extends Annotation>[] fixedSabotages = new Class[] {Signature.class};

    @SuppressWarnings("unchecked")
    private static final Class<? extends Annotation>[] fixedHeaders = new Class[] { AlgorithmHeader.class, KeyIdHeader.class, TypeHeader.class };

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

        for (Object c : parameters) {
            if (c instanceof Signature) {
                Signature s = (Signature) c;

                int index = token.lastIndexOf('.');
                token = token.substring(0, index + 1) + s.value();
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
        for (Object c : parameters) {
            if (c instanceof AlgorithmHeader) {
                AlgorithmHeader b = (AlgorithmHeader) c;
                result.put(ALG, b.value());
            } else if (c instanceof KeyIdHeader) {
                KeyIdHeader b = (KeyIdHeader) c;
                result.put(KID, b.value());
            } else if (c instanceof TypeHeader) {
                TypeHeader b = (TypeHeader) c;
                result.put(TYP, b.value());
            } else {
                throw new IllegalArgumentException("Unsupported header type " + c);
            }
        }
    }

    public Map<String, Object> encodeClaims(ParameterContext parameterContext, ResourceServerConfiguration resolver) {
        Map<String, Object> result = new HashMap<>();

        Optional<AccessToken> a = parameterContext.findAnnotation(AccessToken.class);
        if (a.isPresent()) {
            encode(result, a.get(), resolver);
        }

        encodeCustomClaims(parameterContext, result, resolver);
        
        encodeKnownAnnotationClaims(parameterContext, result, resolver);
        encodeGenericAnnotationClaims(parameterContext, result, resolver);

        transformParameters(result);

        return result;
    }

    protected void encodeCustomClaims(ParameterContext parameterContext, Map<String, Object> result, ResourceServerConfiguration resolver) {
        // for subclassing using additional annotations (which themselves are annotated with Accesstoken)
        // adding them here makes sure that any singular claim annotation always takes precedence 
    }

    protected void transformParameters(Map<String, Object> result) {
        Long issuedAt = (Long) result.get(IAT);
        result.put(IAT, System.currentTimeMillis() / 1000 + issuedAt);

        Long expiresAt = (Long) result.get(EXP);
        result.put(EXP, System.currentTimeMillis() / 1000 + expiresAt);
    }

    protected void encodeKnownAnnotationClaims(ParameterContext parameterContext, Map<String, Object> result, ResourceServerConfiguration resolver) {
        List<Object> parameters = extractKnownClaims(parameterContext);
        if (!parameters.isEmpty()) {
            for (Object c : parameters) {
                if (c instanceof Audience) {
                    Audience b = (Audience) c;
                    result.put(AUD, b.value());
                } else if (c instanceof AuthorizedParty) {
                    AuthorizedParty b = (AuthorizedParty) c;
                    result.put(AZP, b.value());
                } else if (c instanceof ExpiresAt) {
                    ExpiresAt b = (ExpiresAt) c;
                    result.put(EXP, b.value());
                } else if (c instanceof IssuedAt) {
                    IssuedAt b = (IssuedAt) c;
                    result.put(IAT, b.value());
                } else if (c instanceof Issuer) {
                    Issuer b = (Issuer) c;
                    result.put(ISS, b.value());
                } else if (c instanceof Scope) {
                    Scope b = (Scope) c;
                    result.put(SCOPE, String.join(" ", b.value()));
                } else if (c instanceof Subject) {
                    Subject b = (Subject) c;
                    result.put(SUB, b.value());
                } else {
                    throw new IllegalArgumentException("Unsupported claim type " + c);
                }
            }
        }
    }

    @SuppressWarnings("unchecked")
    protected void encodeGenericAnnotationClaims(ParameterContext parameterContext, Map<String, Object> result, ResourceServerConfiguration resolver) {
        List<Object> parameters = extractCustomClaims(parameterContext);
        if (!parameters.isEmpty()) {
            for (Object c : parameters) {
                if (c instanceof BooleanClaim) {
                    BooleanClaim b = (BooleanClaim) c;
                    result.put(b.name(), b.value());
                } else if (c instanceof IntegerClaim) {
                    IntegerClaim b = (IntegerClaim) c;
                    result.put(b.name(), b.value());
                } else if (c instanceof DoubleClaim) {
                    DoubleClaim b = (DoubleClaim) c;
                    result.put(b.name(), b.value());
                } else if (c instanceof StringClaim) {
                    StringClaim b = (StringClaim) c;
                    result.put(b.name(), b.value());
                } else if (c instanceof BooleanArrayClaim) {
                    BooleanArrayClaim b = (BooleanArrayClaim) c;
                    result.put(b.name(), b.value());
                } else if (c instanceof IntegerArrayClaim) {
                    IntegerArrayClaim b = (IntegerArrayClaim) c;
                    result.put(b.name(), b.value());
                } else if (c instanceof DoubleArrayClaim) {
                    DoubleArrayClaim b = (DoubleArrayClaim) c;
                    result.put(b.name(), b.value());
                } else if (c instanceof StringArrayClaim) {
                    StringArrayClaim b = (StringArrayClaim) c;
                    result.put(b.name(), b.value());
                } else if (c instanceof MapClaim) {
                    MapClaim mapClaim = (MapClaim) c;

                    String[] paths = mapClaim.path();

                    Map<String, Object> mapForPath = result;
                    int i = 0;
                    do {
                        Map<String, Object> nextMapForPath = (Map<String, Object>) mapForPath.get(paths[i]);
                        if (nextMapForPath == null) {
                            nextMapForPath = new HashMap<>();
                            mapForPath.put(paths[i], nextMapForPath);
                        }
                        mapForPath = nextMapForPath;

                        i++;
                    } while (i < paths.length);

                    // start adding entries
                    for (Entry entry : mapClaim.entries()) {
                        String[] value = entry.value();

                        if (!entry.alwaysArray() && value.length == 1) {
                            mapForPath.put(entry.name(), valueForType(value[0], entry.type()));
                        } else {
                            // use a list, not an array, as its serialized the same as an array
                            List<Object> list = new ArrayList<>();

                            for (String v : value) {
                                list.add(valueForType(v, entry.type()));
                            }

                            mapForPath.put(entry.name(), list);
                        }
                    }
                } else if (c instanceof JsonClaim) {
                    JsonClaim jsonClaim = (JsonClaim) c;

                    result.put(jsonClaim.name(), new RawValue(jsonClaim.value()));
                } else if (c instanceof NullClaim) {
                    NullClaim b = (NullClaim) c;
                    result.put(b.value(), null);
                } else if (c instanceof MissingClaim) {
                    MissingClaim b = (MissingClaim) c;
                    result.remove(b.value());
                } else {
                    throw new IllegalArgumentException("Unsupported claim type " + c);
                }
            }
        }
    }

    protected Object valueForType(String value, Class<?> type) {
        if (type == String.class) {
            return value;
        } else if (type == Long.class) {
            return Long.parseLong(value);
        } else if (type == Integer.class) {
            return Integer.parseInt(value);
        } else if (type == Boolean.class) {
            return Boolean.parseBoolean(value);
        } else if (type == Double.class) {
            return Double.parseDouble(value);
        } else if (type == Float.class) {
            return Float.parseFloat(value);
        }

        throw new IllegalArgumentException("Cant convert '" + value + "' to " + type.getName());
    }

    protected List<Object> extractCustomClaims(ParameterContext parameterContext) {
        List<Object> parameters = new ArrayList<>();
        for (Class<? extends Annotation> c : customClaims) {
            parameters.addAll(parameterContext.findRepeatableAnnotations(c));
        }
        return parameters;
    }

    protected List<Object> extractAnnotations(ParameterContext parameterContext, Class<? extends Annotation>[] items) {
        List<Object> parameters = new ArrayList<>(items.length);

        for (Class<? extends Annotation> c : items) {
            Optional<?> optional = parameterContext.findAnnotation(c);
            if (optional.isPresent()) {
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
        if (!result.containsKey(ISS)) {
            result.put(ISS, resolver.getProperty(token.by(), "issuer"));
        }
        if (!isBlank(token.subject())) {
            result.put(SUB, token.subject());
        }

        if (!result.containsKey(AUD)) {
            String[] audience = token.audience();
            if (audience != null && audience.length > 0) {
                result.put(AUD, audience);
            } else {
                // TODO resolve from configuration?
            }
        }

        if (!result.containsKey(IAT)) {
            result.put(IAT, token.issuedAt() * 1000);
        }
        if (!result.containsKey(EXP)) {
            result.put(EXP, token.expiresAt() * 1000);
        }

        if (!result.containsKey(SCOPE)) {
            if (!isBlank(token.scope())) {
                result.put(SCOPE, token.scope());
            }
        }

        if (!result.containsKey(AZP)) {
            if (!isBlank(token.authorizedParty())) {
                result.put(AZP, token.authorizedParty());
            }
        }
    }

    protected boolean isBlank(String[] scope) {
        return scope == null || scope.length == 0;
    }

    protected boolean isBlank(String subject) {
        return subject == null || subject.isEmpty();
    }
}
