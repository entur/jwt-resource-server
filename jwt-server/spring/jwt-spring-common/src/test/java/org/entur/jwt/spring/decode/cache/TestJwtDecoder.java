package org.entur.jwt.spring.decode.cache;

import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Function;

/**
 * {@link JwtDecoder} for tests: returns the JWT registered for a token (or computed by a function),
 * and counts how many times each token was decoded.
 */
class TestJwtDecoder implements JwtDecoder {

    private final Map<String, Jwt> jwts = new ConcurrentHashMap<>();
    private final Map<String, AtomicInteger> counts = new ConcurrentHashMap<>();
    private volatile Function<String, Jwt> function = token -> null;

    TestJwtDecoder returning(String token, Jwt jwt) {
        jwts.put(token, jwt);
        return this;
    }

    TestJwtDecoder answering(Function<String, Jwt> function) {
        this.function = function;
        return this;
    }

    @Override
    public Jwt decode(String token) throws JwtException {
        counts.computeIfAbsent(token, k -> new AtomicInteger()).incrementAndGet();
        Jwt jwt = jwts.get(token);
        if (jwt == null) {
            jwt = function.apply(token);
        }
        return jwt;
    }

    int count(String token) {
        AtomicInteger count = counts.get(token);
        return count == null ? 0 : count.get();
    }
}
