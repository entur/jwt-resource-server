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
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

public class DefaultAuthorizationServerEncoder implements AuthorizationServerEncoder {

    // like the JWT library, write dates in non-standard claims as milliseconds
    private static final JsonMapper JSON_MAPPER = JsonMapper.builder().enable(DateTimeFeature.WRITE_DATES_AS_TIMESTAMPS).build();

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

    private final KeyPair keyPair;

    public DefaultAuthorizationServerEncoder() {
        keyPair = createKeyPair();
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

    @Override
    public String getJsonWebKeys(Annotation annotation) {
        RSAPublicKey pk = (RSAPublicKey) keyPair.getPublic();
        String n = toBase64UrlUInt(pk.getModulus());
        String e = toBase64UrlUInt(pk.getPublicExponent());

        return String.format("{\"keys\":[{\"kid\":\"%s\",\"kty\":\"RSA\",\"alg\":\"RS256\",\"use\":\"sig\",\"n\":\"%s\",\"e\":\"%s\"}]}", Integer.toString(pk.hashCode()), n, e);
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
        if (!headers.containsKey("typ")) {
            headers.put("typ", "JWT");
        }
        if (!headers.containsKey("kid")) {
            headers.put("kid", Integer.toString(keyPair.getPublic().hashCode()));
        }

        JwtBuilder builder = Jwts.builder().setHeader(headers).content(toJson(claims));

        SignatureAlgorithm algorithm = SignatureAlgorithm.RS256;
        String algorithmName = (String) headers.get("alg");
        if (algorithmName != null) {
            // XXX spawn key types on demand
            algorithm = SignatureAlgorithm.forName(algorithmName);
        }

        return builder.signWith(keyPair.getPrivate(), algorithm).compact();
    }

    private byte[] toJson(Map<String, Object> claims) {
        // the JWT library drops claims with null values, so let it convert the standard claims (e.g. dates to seconds),
        // then add back the null values and serialize the claims ourselves
        Map<String, Object> payload = new LinkedHashMap<>(Jwts.claims().add(claims).build());
        for (Map.Entry<String, Object> entry : claims.entrySet()) {
            if (entry.getValue() == null) {
                payload.put(entry.getKey(), null);
            }
        }
        return JSON_MAPPER.writeValueAsBytes(payload);
    }
}
