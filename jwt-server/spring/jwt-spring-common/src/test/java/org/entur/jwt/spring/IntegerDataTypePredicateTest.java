package org.entur.jwt.spring;

import org.junit.jupiter.api.Test;

import java.math.BigDecimal;
import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class IntegerDataTypePredicateTest {

    private final IntegerDataTypePredicate predicate = new IntegerDataTypePredicate();

    @Test
    void matchesIntegralTypes() {
        assertTrue(predicate.test(1L));
        assertTrue(predicate.test(1));
        assertTrue(predicate.test((short) 1));
        assertTrue(predicate.test((byte) 1));
        assertTrue(predicate.test(BigInteger.ONE));
    }

    @Test
    void doesNotMatchOtherTypes() {
        assertFalse(predicate.test(1.0d));
        assertFalse(predicate.test(1.0f));
        assertFalse(predicate.test(BigDecimal.ONE));
        assertFalse(predicate.test("1"));
    }

    @Test
    void doesNotMatchNull() {
        assertFalse(predicate.test(null));
    }
}
