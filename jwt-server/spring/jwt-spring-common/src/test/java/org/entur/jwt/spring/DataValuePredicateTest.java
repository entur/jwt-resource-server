package org.entur.jwt.spring;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DataValuePredicateTest {

    @Test
    void matchesEqualValue() {
        DataValuePredicate<String> predicate = new DataValuePredicate<>("expected");
        assertTrue(predicate.test("expected"));
    }

    @Test
    void doesNotMatchDifferentValue() {
        DataValuePredicate<String> predicate = new DataValuePredicate<>("expected");
        assertFalse(predicate.test("other"));
    }

    @Test
    void doesNotMatchNull() {
        DataValuePredicate<String> predicate = new DataValuePredicate<>("expected");
        assertFalse(predicate.test(null));
    }
}
