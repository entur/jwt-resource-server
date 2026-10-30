package org.entur.jwt.spring;

import org.junit.jupiter.api.Test;

import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class IntegerDataValuePredicateTest {

    @Test
    void matchesEqualValueOfAnyIntegralType() {
        IntegerDataValuePredicate predicate = new IntegerDataValuePredicate(2);
        assertTrue(predicate.test(2L));
        assertTrue(predicate.test(2));
        assertTrue(predicate.test((short) 2));
        assertTrue(predicate.test((byte) 2));
        assertTrue(predicate.test(BigInteger.TWO));
    }

    @Test
    void doesNotMatchDifferentValue() {
        IntegerDataValuePredicate predicate = new IntegerDataValuePredicate(2);
        assertFalse(predicate.test(3L));
        assertFalse(predicate.test(3));
        // would be 2 if truncated to a long
        assertFalse(predicate.test(BigInteger.ONE.shiftLeft(64).add(BigInteger.TWO)));
    }

    @Test
    void doesNotMatchOtherTypes() {
        IntegerDataValuePredicate predicate = new IntegerDataValuePredicate(2);
        assertFalse(predicate.test(2.0d));
        assertFalse(predicate.test("2"));
    }

    @Test
    void doesNotMatchNull() {
        assertFalse(new IntegerDataValuePredicate(2).test(null));
    }
}
