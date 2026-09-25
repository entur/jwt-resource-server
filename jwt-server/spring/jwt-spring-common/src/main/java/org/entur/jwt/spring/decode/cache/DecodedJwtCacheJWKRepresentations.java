package org.entur.jwt.spring.decode.cache;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import org.jspecify.annotations.NonNull;

import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * An immutable snapshot of the "active" keys (by key id) of a {@link JWKSet}, each
 * represented by its full JWK JSON representation (not just the key id or its RFC 7638
 * thumbprint). Comparing two instances for equality therefore also detects metadata-only
 * changes (e.g. "alg", "use", "x5c") affecting key selection, not just changes to the
 * cryptographic key material itself.
 * <p>
 * Several JWKs may share the same key id (this is allowed by the JWK Set spec, even though
 * discouraged). All representations advertised for a given key id are grouped together; if
 * any single one of them changes, is added or removed, the whole group for that key id is
 * considered changed, so any cached/validated JWT referencing that key id must be evicted -
 * there is no way to tell from the kid alone which of the (possibly several) keys was
 * actually used to sign a given JWT.
 * <p>
 * Keys are excluded from the snapshot if:
 * <ul>
 *     <li>they have no (or an empty) key id, since they can never be looked up by kid, or</li>
 *     <li>they fall outside their own "nbf" (not before) / "exp" (expiration) validity window,
 *     relative to the time the snapshot is taken; such a key must not be treated as an active
 *     signing key.</li>
 * </ul>
 */
public class DecodedJwtCacheJWKRepresentations {

    private static final DecodedJwtCacheJWKRepresentations EMPTY = new DecodedJwtCacheJWKRepresentations(Collections.emptyMap());

    // kid -> set of full JWK representations advertised for that kid
    protected final Map<String, Set<Map<String, Object>>> keys;

    protected DecodedJwtCacheJWKRepresentations(Map<String, Set<Map<String, Object>>> keys) {
        this.keys = keys;
    }

    protected static DecodedJwtCacheJWKRepresentations empty() {
        return EMPTY;
    }

    protected static DecodedJwtCacheJWKRepresentations of(JWKSet jwkSet) {
        Map<String, Set<Map<String, Object>>> keyRepresentations = getKeyRepresentations(jwkSet);
        if (keyRepresentations.isEmpty()) {
            return EMPTY;
        }
        return new DecodedJwtCacheJWKRepresentations(keyRepresentations);
    }

    protected static @NonNull Map<String, Set<Map<String, Object>>> getKeyRepresentations(JWKSet jwkSet) {
        Map<String, Set<Map<String, Object>>> keyRepresentations = HashMap.newHashMap(jwkSet.getKeys().size() * 2);
        Date now = new Date();
        for (JWK key : jwkSet.getKeys()) {
            String keyId = key.getKeyID();
            if (keyId == null || keyId.isEmpty()) {
                continue;
            }

            // exclude keys outside their own "nbf"/"exp" validity window (if set);
            // such a key must not be treated as an active signing key, so any JWT
            // referencing its kid is neither cached nor kept in the cache
            Date notBefore = key.getNotBeforeTime();
            if (notBefore != null && notBefore.after(now)) {
                continue;
            }
            Date expirationTime = key.getExpirationTime();
            if (expirationTime != null && expirationTime.before(now)) {
                continue;
            }

            keyRepresentations
                    .computeIfAbsent(keyId, k -> new HashSet<>())
                    .add(Map.copyOf(key.toJSONObject()));
        }
        Map<String, Set<Map<String, Object>>> result = HashMap.newHashMap(keyRepresentations.size() * 2);
        for (Map.Entry<String, Set<Map<String, Object>>> entry : keyRepresentations.entrySet()) {
            result.put(entry.getKey(), Set.copyOf(entry.getValue()));
        }
        return Map.copyOf(result);
    }

    public boolean isEmpty() {
        return keys.isEmpty();
    }

    /**
     * @return true if the given key id is currently active (present, with at least one
     * key within its validity window).
     */
    public boolean contains(String keyId) {
        return keys.containsKey(keyId);
    }

    /**
     * @return true if the given key id is present with the exact same set of JWK
     * representations in both this and the other snapshot; if any key sharing this kid
     * changed, was added or removed, this returns false - a kid re-used for a
     * rotated/different key (or one that has left/entered its validity window) is not
     * considered "the same".
     */
    public boolean hasSameKey(String keyId, DecodedJwtCacheJWKRepresentations other) {
        Set<Map<String, Object>> representations = keys.get(keyId);
        return representations != null && representations.equals(other.keys.get(keyId));
    }

    /**
     * @return true if this and the other snapshot advertise exactly the same set of active
     * keys, each key id with the exact same set of full JWK representations.
     */
    public boolean hasSameKeys(DecodedJwtCacheJWKRepresentations other) {
        return this.keys.equals(other.keys);
    }

    /**
     * Compares this (current) snapshot with a previous one and returns the set of key ids
     * that are proven unchanged - present with the exact same set of JWK representations
     * in both snapshots. This is a safe, whitelist-style check: a key id is only included
     * if it can be positively confirmed to be identical; anything not returned (added,
     * removed, or changed key ids, including any key sharing a kid with several JWKs where
     * at least one of them differs) must be treated as changed, so JWTs cached under it
     * are not carried over.
     *
     * @return {@code keySet()} of the current snapshot if {@link #hasSameKeys(DecodedJwtCacheJWKRepresentations)} would be true
     */
    public Set<String> unchangedKeyIds(DecodedJwtCacheJWKRepresentations previous) {
        if (keys.equals(previous.keys)) {
            return keys.keySet();
        }
        Set<String> unchangedKeyIds = new HashSet<>();
        for (Map.Entry<String, Set<Map<String, Object>>> entry : keys.entrySet()) {
            if (entry.getValue().equals(previous.keys.get(entry.getKey()))) {
                unchangedKeyIds.add(entry.getKey());
            }
        }
        return Set.copyOf(unchangedKeyIds);
    }

    @Override
    public String toString() {
        return keys.keySet().toString();
    }
}
