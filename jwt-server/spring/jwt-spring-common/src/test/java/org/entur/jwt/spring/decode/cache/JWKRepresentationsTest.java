package org.entur.jwt.spring.decode.cache;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import org.junit.jupiter.api.Test;

import java.util.Date;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JWKRepresentationsTest {

    private static JWK key(String kid) throws Exception {
        return new OctetSequenceKey.Builder("secret-material".getBytes()).keyID(kid).build();
    }

    private static JWK key(String kid, String algorithm) throws Exception {
        return new OctetSequenceKey.Builder("secret-material".getBytes())
                .keyID(kid)
                .algorithm(new Algorithm(algorithm))
                .build();
    }

    private static JWK key(String kid, byte[] secret) {
        return new OctetSequenceKey.Builder(secret).keyID(kid).build();
    }

    private static JWK keyWithValidityWindow(String kid, Date notBefore, Date expirationTime) {
        return new OctetSequenceKey.Builder("secret-material".getBytes())
                .keyID(kid)
                .notBeforeTime(notBefore)
                .expirationTime(expirationTime)
                .build();
    }

    private static JWKSet jwkSet(JWK... keys) {
        return new JWKSet(List.of(keys));
    }

    @Test
    void emptyIsEmptyAndContainsNothing() {
        JWKRepresentations empty = JWKRepresentations.empty();

        assertTrue(empty.isEmpty());
        assertFalse(empty.contains("kid1"));
    }

    @Test
    void ofEmptyJwkSetReturnsEmptyRepresentations() {
        JWKRepresentations representations = JWKRepresentations.of(new JWKSet());

        assertTrue(representations.isEmpty());
    }

    @Test
    void ofJwkSetContainsAdvertisedKeyId() throws Exception {
        JWKRepresentations representations = JWKRepresentations.of(jwkSet(key("kid1")));

        assertFalse(representations.isEmpty());
        assertTrue(representations.contains("kid1"));
        assertFalse(representations.contains("kid2"));
    }

    @Test
    void ofJwkSetExcludesKeyWithNoKeyId() {
        JWK noKid = new OctetSequenceKey.Builder("secret-material".getBytes()).build();

        JWKRepresentations representations = JWKRepresentations.of(jwkSet(noKid));

        assertTrue(representations.isEmpty());
    }

    @Test
    void ofJwkSetExcludesKeyWithEmptyKeyId() {
        JWK emptyKid = new OctetSequenceKey.Builder("secret-material".getBytes()).keyID("").build();

        JWKRepresentations representations = JWKRepresentations.of(jwkSet(emptyKid));

        assertTrue(representations.isEmpty());
    }

    @Test
    void ofJwkSetExcludesKeyThatIsNotYetValid() {
        Date oneHourFromNow = new Date(System.currentTimeMillis() + 3600_000L);
        JWK notYetValid = keyWithValidityWindow("kid1", oneHourFromNow, null);

        JWKRepresentations representations = JWKRepresentations.of(jwkSet(notYetValid));

        assertTrue(representations.isEmpty());
        assertFalse(representations.contains("kid1"));
    }

    @Test
    void ofJwkSetExcludesKeyThatHasExpired() {
        Date oneHourAgo = new Date(System.currentTimeMillis() - 3600_000L);
        JWK expired = keyWithValidityWindow("kid1", null, oneHourAgo);

        JWKRepresentations representations = JWKRepresentations.of(jwkSet(expired));

        assertTrue(representations.isEmpty());
        assertFalse(representations.contains("kid1"));
    }

    @Test
    void ofJwkSetIncludesKeyCurrentlyWithinItsValidityWindow() {
        Date oneHourAgo = new Date(System.currentTimeMillis() - 3600_000L);
        Date oneHourFromNow = new Date(System.currentTimeMillis() + 3600_000L);
        JWK currentlyValid = keyWithValidityWindow("kid1", oneHourAgo, oneHourFromNow);

        JWKRepresentations representations = JWKRepresentations.of(jwkSet(currentlyValid));

        assertTrue(representations.contains("kid1"));
    }

    @Test
    void ofJwkSetGroupsMultipleKeysSharingTheSameKeyId() throws Exception {
        JWKRepresentations representations = JWKRepresentations.of(
                jwkSet(key("kid1", "HS256"), key("kid1", "HS512")));

        // both keys are grouped under the same (still active/ambiguous) key id
        assertTrue(representations.contains("kid1"));
    }

    @Test
    void hasSameKeyIsTrueForIdenticalSingleKeyRepresentation() throws Exception {
        JWKRepresentations a = JWKRepresentations.of(jwkSet(key("kid1")));
        JWKRepresentations b = JWKRepresentations.of(jwkSet(key("kid1")));

        assertTrue(a.hasSameKey("kid1", b));
        assertTrue(a.hasSameKeys(b));
    }

    @Test
    void hasSameKeyIsFalseWhenKeyMetadataChanges() throws Exception {
        // same kid and key material, but different algorithm metadata
        JWKRepresentations a = JWKRepresentations.of(jwkSet(key("kid1", "HS256")));
        JWKRepresentations b = JWKRepresentations.of(jwkSet(key("kid1", "HS512")));

        assertFalse(a.hasSameKey("kid1", b));
        assertFalse(a.hasSameKeys(b));
    }

    @Test
    void hasSameKeyIsFalseWhenKeyMaterialChanges() {
        JWKRepresentations a = JWKRepresentations.of(jwkSet(key("kid1", "secret-a".getBytes())));
        JWKRepresentations b = JWKRepresentations.of(jwkSet(key("kid1", "secret-b".getBytes())));

        assertFalse(a.hasSameKey("kid1", b));
        assertFalse(a.hasSameKeys(b));
    }

    @Test
    void hasSameKeyIsFalseWhenKeyIdIsAbsentInOther() throws Exception {
        JWKRepresentations a = JWKRepresentations.of(jwkSet(key("kid1")));
        JWKRepresentations b = JWKRepresentations.empty();

        assertFalse(a.hasSameKey("kid1", b));
        assertFalse(b.hasSameKey("kid1", a));
        assertFalse(a.hasSameKeys(b));
    }

    @Test
    void hasSameKeyIsTrueWhenGroupOfDuplicateKidKeysIsUnchanged() throws Exception {
        JWKRepresentations a = JWKRepresentations.of(jwkSet(key("kid1", "HS256"), key("kid1", "HS512")));
        JWKRepresentations b = JWKRepresentations.of(jwkSet(key("kid1", "HS512"), key("kid1", "HS256")));

        // set semantics -> order of the duplicate-kid keys in the JWKS doesn't matter
        assertTrue(a.hasSameKey("kid1", b));
        assertTrue(a.hasSameKeys(b));
    }

    @Test
    void hasSameKeyIsFalseWhenOneOfTheDuplicateKidKeysIsRemoved() throws Exception {
        JWKRepresentations a = JWKRepresentations.of(jwkSet(key("kid1", "HS256"), key("kid1", "HS512")));
        JWKRepresentations b = JWKRepresentations.of(jwkSet(key("kid1", "HS256")));

        // any change (here: fewer keys) within the group for the kid must be
        // treated as changed, since it's not possible to tell from the kid alone
        // which of the (possibly several) keys signed a given JWT
        assertFalse(a.hasSameKey("kid1", b));
        assertFalse(a.hasSameKeys(b));
    }

    @Test
    void hasSameKeysIsTrueForTwoEmptyInstances() {
        assertTrue(JWKRepresentations.empty().hasSameKeys(JWKRepresentations.empty()));
    }

    @Test
    void hasSameKeysIsFalseWhenAnUnrelatedKeyIdIsAdded() throws Exception {
        JWKRepresentations a = JWKRepresentations.of(jwkSet(key("kid1")));
        JWKRepresentations b = JWKRepresentations.of(jwkSet(key("kid1"), key("kid2")));

        assertFalse(a.hasSameKeys(b));
        // the unaffected key id is still reported as unchanged
        assertTrue(a.hasSameKey("kid1", b));
    }

    @Test
    void unchangedKeyIdsContainsAllKeyIdsWhenNothingChanged() throws Exception {
        JWKRepresentations a = JWKRepresentations.of(jwkSet(key("kid1"), key("kid2")));
        JWKRepresentations b = JWKRepresentations.of(jwkSet(key("kid1"), key("kid2")));

        assertEquals(Set.of("kid1", "kid2"), a.unchangedKeyIds(b));
        assertEquals(Set.of("kid1", "kid2"), b.unchangedKeyIds(a));
    }

    @Test
    void unchangedKeyIdsBetweenTwoEmptyInstancesIsEmpty() {
        assertEquals(Set.of(), JWKRepresentations.empty().unchangedKeyIds(JWKRepresentations.empty()));
    }

    @Test
    void unchangedKeyIdsExcludesAddedKeyId() throws Exception {
        JWKRepresentations previous = JWKRepresentations.of(jwkSet(key("kid1")));
        JWKRepresentations current = JWKRepresentations.of(jwkSet(key("kid1"), key("kid2")));

        assertEquals(Set.of("kid1"), current.unchangedKeyIds(previous));
    }

    @Test
    void unchangedKeyIdsExcludesRemovedKeyId() throws Exception {
        JWKRepresentations previous = JWKRepresentations.of(jwkSet(key("kid1"), key("kid2")));
        JWKRepresentations current = JWKRepresentations.of(jwkSet(key("kid1")));

        assertEquals(Set.of("kid1"), current.unchangedKeyIds(previous));
    }

    @Test
    void unchangedKeyIdsExcludesKeyIdWithChangedMetadataButKeepsUnaffectedKeyIds() throws Exception {
        JWKRepresentations previous = JWKRepresentations.of(jwkSet(key("kid1", "HS256"), key("kid2")));
        JWKRepresentations current = JWKRepresentations.of(jwkSet(key("kid1", "HS512"), key("kid2")));

        assertEquals(Set.of("kid2"), current.unchangedKeyIds(previous));
    }

    @Test
    void unchangedKeyIdsExcludesKeyIdWhenOneOfSeveralKeysSharingItIsRemoved() throws Exception {
        JWKRepresentations previous = JWKRepresentations.of(jwkSet(key("kid1", "HS256"), key("kid1", "HS512")));
        JWKRepresentations current = JWKRepresentations.of(jwkSet(key("kid1", "HS256")));

        assertEquals(Set.of(), current.unchangedKeyIds(previous));
    }

    @Test
    void unchangedKeyIdsIgnoresOrderOfDuplicateKidKeys() throws Exception {
        JWKRepresentations previous = JWKRepresentations.of(jwkSet(key("kid1", "HS256"), key("kid1", "HS512")));
        JWKRepresentations current = JWKRepresentations.of(jwkSet(key("kid1", "HS512"), key("kid1", "HS256")));

        assertEquals(Set.of("kid1"), current.unchangedKeyIds(previous));
    }
}
