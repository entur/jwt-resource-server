package org.entur.jwt.junit5.impl;

import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.entur.jwt.junit5.AuthorizationServerEncoder;
import tools.jackson.databind.cfg.DateTimeFeature;
import tools.jackson.databind.json.JsonMapper;

import java.lang.annotation.Annotation;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Calendar;
import java.util.Date;
import java.util.EnumMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

public class DefaultAuthorizationServerEncoder implements AuthorizationServerEncoder {

    // like the JWT library, write dates in other claims than the date claims as milliseconds
    private static final JsonMapper JSON_MAPPER = JsonMapper.builder().enable(DateTimeFeature.WRITE_DATES_AS_TIMESTAMPS).build();

    // claims with a NumericDate (seconds) value
    private static final Set<String> dateClaims = Set.of("exp", "nbf", "iat");

    private static final Set<String> standardClaims;

    static {
        Set<String> claims = new HashSet<>(); // thread safe for reading

        claims.add("iss");
        claims.add("sub");
        claims.add("aud");
        claims.add("exp");
        claims.add("nbf");
        claims.add("iat");
        claims.add("jti");

        claims.add("name");
        claims.add("given_name");
        claims.add("family_name");
        claims.add("middle_name");
        claims.add("nickname");
        claims.add("preferred_username");
        claims.add("profile");
        claims.add("picture");
        claims.add("website");
        claims.add("email");
        claims.add("email_verified");
        claims.add("gender");
        claims.add("birthdate");
        claims.add("zoneinfo");
        claims.add("locale");
        claims.add("phone_number");
        claims.add("phone_number_verified");
        claims.add("address");
        claims.add("updated_at");

        standardClaims = claims;
    }

    public boolean isStandardClaim(String name) {
        return standardClaims.contains(name);
    }

    /**
     * Elliptic curves for the ECDSA algorithms, each with its JSON Web Key and Java names and coordinate size in bytes.
     */

    protected enum EllipticCurve {
        P_256("ES256", "P-256", "secp256r1", 32),
        P_384("ES384", "P-384", "secp384r1", 48),
        P_521("ES512", "P-521", "secp521r1", 66);

        private final String algorithm;
        private final String jwkName;
        private final String standardName;
        private final int coordinateSize;

        EllipticCurve(String algorithm, String jwkName, String standardName, int coordinateSize) {
            this.algorithm = algorithm;
            this.jwkName = jwkName;
            this.standardName = standardName;
            this.coordinateSize = coordinateSize;
        }

        public static EllipticCurve forAlgorithm(String algorithm) {
            for (EllipticCurve curve : values()) {
                if (curve.algorithm.equals(algorithm)) {
                    return curve;
                }
            }
            return null;
        }
    }

    private final KeyPair keyPair;

    // note: create all keys up front, so that the JSON Web Keys do not change
    private final Map<EllipticCurve, KeyPair> ellipticCurveKeyPairs = new EnumMap<>(EllipticCurve.class);

    public DefaultAuthorizationServerEncoder() {
        keyPair = createKeyPair();
        for (EllipticCurve curve : EllipticCurve.values()) {
            ellipticCurveKeyPairs.put(curve, createEllipticCurveKeyPair(curve));
        }
    }

    protected KeyPair createKeyPair() {
        KeyPairGenerator keyGen;
        try {
            keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048);

            return keyGen.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    protected KeyPair createEllipticCurveKeyPair(EllipticCurve curve) {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
            keyGen.initialize(new ECGenParameterSpec(curve.standardName));

            return keyGen.generateKeyPair();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public String getJsonWebKeys(Annotation annotation) {
        RSAPublicKey pk = (RSAPublicKey) keyPair.getPublic();
        String n = toBase64UrlUInt(pk.getModulus());
        String e = toBase64UrlUInt(pk.getPublicExponent());

        // no algorithm for the RSA key, so that it can verify all RSA algorithms (RS256, RS384, RS512, PS256, PS384 and PS512)
        StringBuilder builder = new StringBuilder();
        builder.append(String.format("{\"keys\":[{\"kid\":\"%s\",\"kty\":\"RSA\",\"use\":\"sig\",\"n\":\"%s\",\"e\":\"%s\"}", getKeyId(pk), n, e));

        for (Map.Entry<EllipticCurve, KeyPair> entry : ellipticCurveKeyPairs.entrySet()) {
            EllipticCurve curve = entry.getKey();
            ECPublicKey ecPublicKey = (ECPublicKey) entry.getValue().getPublic();

            String x = toBase64UrlCoordinate(ecPublicKey.getW().getAffineX(), curve.coordinateSize);
            String y = toBase64UrlCoordinate(ecPublicKey.getW().getAffineY(), curve.coordinateSize);

            builder.append(String.format(",{\"kid\":\"%s\",\"kty\":\"EC\",\"use\":\"sig\",\"crv\":\"%s\",\"x\":\"%s\",\"y\":\"%s\"}", getKeyId(ecPublicKey), curve.jwkName, x, y));
        }
        builder.append("]}");

        return builder.toString();
    }

    protected String getKeyId(PublicKey publicKey) {
        return Integer.toString(publicKey.hashCode());
    }

    /**
     * Encode an elliptic curve coordinate as a fixed size (unsigned, zero-padded) value, without padding (RFC 7518 section 6.2.1.2).
     *
     * @param value positive value
     * @param size size in bytes
     * @return encoded value
     */

    protected static String toBase64UrlCoordinate(BigInteger value, int size) {
        byte[] bytes = value.toByteArray();
        byte[] coordinate = new byte[size];
        // copy the least significant bytes, so that any sign byte is removed and leading zeros are added
        int length = Math.min(bytes.length, size);
        System.arraycopy(bytes, bytes.length - length, coordinate, size - length, length);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(coordinate);
    }

    /**
     * Encode as Base64urlUInt, i.e. unsigned, without leading zero bytes and without padding (RFC 7518 section 2).
     *
     * @param value positive value
     * @return encoded value
     */

    protected static String toBase64UrlUInt(BigInteger value) {
        byte[] bytes = value.toByteArray();
        if (bytes.length > 1 && bytes[0] == 0) {
            // remove the sign byte
            bytes = Arrays.copyOfRange(bytes, 1, bytes.length);
        }
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    @Override
    public String getToken(Annotation authorizationServer, Map<String, Object> claims, Map<String, Object> headers) {
        SignatureAlgorithm algorithm = SignatureAlgorithm.RS256;
        String algorithmName = (String) headers.get("alg");
        if (algorithmName != null) {
            algorithm = SignatureAlgorithm.forName(algorithmName);
        }
        KeyPair signingKeyPair = getKeyPair(algorithm);

        if (!headers.containsKey("typ")) {
            headers.put("typ", "JWT");
        }
        if (!headers.containsKey("kid")) {
            headers.put("kid", getKeyId(signingKeyPair.getPublic()));
        }

        JwtBuilder builder = Jwts.builder().setHeader(headers).content(toJson(claims));

        return builder.signWith(signingKeyPair.getPrivate(), algorithm).compact();
    }

    protected KeyPair getKeyPair(SignatureAlgorithm algorithm) {
        if (algorithm.isRsa()) {
            return keyPair;
        }
        EllipticCurve curve = EllipticCurve.forAlgorithm(algorithm.getValue());
        if (curve != null) {
            return ellipticCurveKeyPairs.get(curve);
        }
        throw new IllegalArgumentException("Unsupported algorithm " + algorithm.getValue() + ", expected RS256, RS384, RS512, PS256, PS384, PS512, ES256, ES384 or ES512");
    }

    private byte[] toJson(Map<String, Object> claims) {
        // serialize the claims ourselves, as given: the JWT library converts or rejects standard claims of other types
        // (and drops null and empty values), so tokens with malformed standard claims could not be created
        Map<String, Object> payload = new LinkedHashMap<>(claims);

        // like the JWT library, write dates in the date claims as seconds
        for (String name : dateClaims) {
            Object value = payload.get(name);
            if (value instanceof Date date) {
                payload.put(name, date.getTime() / 1000);
            } else if (value instanceof Calendar calendar) {
                payload.put(name, calendar.getTimeInMillis() / 1000);
            }
        }
        return JSON_MAPPER.writeValueAsBytes(payload);
    }
}
