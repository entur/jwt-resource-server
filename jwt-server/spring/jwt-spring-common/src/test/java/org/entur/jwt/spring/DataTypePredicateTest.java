package org.entur.jwt.spring;

import org.junit.jupiter.api.Test;

import java.util.function.Predicate;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DataTypePredicateTest {

    @Test
    void matchesExactType() {
        DataTypePredicate<String> predicate = new DataTypePredicate<>(String.class);
        assertTrue(predicate.test("hello"));
    }

    @Test
    @SuppressWarnings({"unchecked", "rawtypes"})
    void matchesWhenConfiguredClassIsSubtypeOfActualValueType() {
        // The predicate checks t.getClass().isAssignableFrom(clazz), i.e. whether the
        // configured class is a subtype of (or equal to) the actual runtime type of t.
        Predicate<Object> predicate = new DataTypePredicate(String.class);
        assertTrue(predicate.test(new Object()));
    }

    @Test
    @SuppressWarnings({"unchecked", "rawtypes"})
    void doesNotMatchWhenConfiguredClassIsNotSubtypeOfActualValueType() {
        Predicate<Object> predicate = new DataTypePredicate(Object.class);
        assertFalse(predicate.test("hello"));
    }

    @Test
    void doesNotMatchNull() {
        DataTypePredicate<String> predicate = new DataTypePredicate<>(String.class);
        assertFalse(predicate.test(null));
    }
}
