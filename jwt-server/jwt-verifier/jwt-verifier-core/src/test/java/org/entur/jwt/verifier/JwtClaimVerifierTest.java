package org.entur.jwt.verifier;

import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.HashMap;
import java.util.Map;

import org.entur.jwt.jwk.JwksException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

public class JwtClaimVerifierTest {

    private MapJwtClaimExtractor jwtClaimExtractor = new MapJwtClaimExtractor();
    private MapJwtVerifier verifier = new MapJwtVerifier();
    private Map<String, Class<?>> types = new HashMap<>();
    private Map<String, Object> values = new HashMap<>();
    private JwtClaimVerifier<Map<String, Object>> claimVerifier = new JwtClaimVerifier<>(verifier, jwtClaimExtractor, types, values);

    private String token = "a.b.c";

    @AfterEach
    public void afterEach() {
        verifier.clear();
        types.clear();
        values.clear();
    }

    @Test
    public void testVerifyValues() throws JwtException, JwksException {
        forDataValue("abc", "abc");
        claimVerifier.verify(token);
    }

    @Test
    public void testRejectsInvalidValue() throws JwtException, JwksException {
        forDataValue(1L, "abcdef");
        assertThrows(JwtClaimException.class, () -> {
            claimVerifier.verify(token);
        });
    }

    @Test
    public void testRejectsInvalidDataType() throws JwtException, JwksException {
        forDataType("aString", Integer.class);
        assertThrows(JwtClaimException.class, () -> {
            claimVerifier.verify(token);
        });
    }

    public void forDataType(Object value, Class<?> dataType) {
        String claimName = "https://my.namespace/key";

        Map<String, Object> claims = new HashMap<>();
        claims.put(claimName, value);

        verifier.put(token, claims);

        types.put(claimName, dataType);
    }

    public void forDataValue(Object value, Object expected) {
        String claimName = "https://my.namespace/key";

        Map<String, Object> claims = new HashMap<>();
        claims.put(claimName, value);

        verifier.put(token, claims);

        values.put(claimName, expected);
    }

    @Test
    public void testVerifyIntegerOrLongDataTypes() throws JwtException, JwksException {
        forDataType(1, Integer.class);
        claimVerifier.verify(token);

        forDataType(1L, Long.class);
        claimVerifier.verify(token);

        // and cross-values
        forDataType(1L, Integer.class);
        claimVerifier.verify(token);

        forDataType(1, Long.class);
        claimVerifier.verify(token);
    }

    @Test
    public void testVerifyIntegerOrLongDataValues() throws JwtException, JwksException {
        forDataValue(1, 1);
        claimVerifier.verify(token);

        forDataValue(1L, 1L);
        claimVerifier.verify(token);

        // and cross-values
        forDataValue(1L, 1);
        claimVerifier.verify(token);

        forDataValue(1L, 1);
        claimVerifier.verify(token);
    }
}
