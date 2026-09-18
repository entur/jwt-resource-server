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
    void doesNotMatchWhenActualValueTypeIsNotSubtypeOfConfiguredClass() {
        Predicate<Object> predicate = new DataTypePredicate(String.class);
        assertFalse(predicate.test(new Object()));
    }

    @Test
    @SuppressWarnings({"unchecked", "rawtypes"})
    void matchesWhenActualValueTypeIsSubtypeOfConfiguredClass() {
        Predicate<Object> predicate = new DataTypePredicate(Object.class);
        assertTrue(predicate.test("hello"));
    }

    @Test
    void doesNotMatchNull() {
        DataTypePredicate<String> predicate = new DataTypePredicate<>(String.class);
        assertFalse(predicate.test(null));
    }
}
