package org.entur.jwt.junit5.impl;

import java.lang.annotation.Annotation;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.entur.jwt.junit5.AuthorizationServerEncoder;

import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

public class DefaultAuthorizationServerEncoder implements AuthorizationServerEncoder {

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
        String n = Base64.getUrlEncoder().encodeToString(pk.getModulus().toByteArray());
        String e = Base64.getUrlEncoder().encodeToString(pk.getPublicExponent().toByteArray());

        return String.format("{\"keys\":[{\"kid\":\"%s\",\"kty\":\"RSA\",\"alg\":\"RS256\",\"use\":\"sig\",\"n\":\"%s\",\"e\":\"%s\"}]}", Integer.toString(pk.hashCode()), n, e);
    }

    @Override
    public String getToken(Annotation authorizationServer, Map<String, Object> claims, Map<String, Object> headers) {
        if (!headers.containsKey("typ")) {
            headers.put("typ", "JWT");
        }
        if (!headers.containsKey("kid")) {
            headers.put("kid", Integer.toString(keyPair.getPublic().hashCode()));
        }

        JwtBuilder builder = Jwts.builder().setHeader(headers).setClaims(claims);

        SignatureAlgorithm algorithm = SignatureAlgorithm.RS256;
        String algorithmName = (String) headers.get("alg");
        if (algorithmName != null) {
            // XXX spawn key types on demand
            algorithm = SignatureAlgorithm.forName(algorithmName);
        }

        return builder.signWith(keyPair.getPrivate(), algorithm).compact();
    }
}
