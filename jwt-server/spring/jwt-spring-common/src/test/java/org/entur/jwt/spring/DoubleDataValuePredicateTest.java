package org.entur.jwt.spring;

import org.junit.jupiter.api.Test;

import java.math.BigDecimal;
import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DoubleDataValuePredicateTest {

    @Test
    void matchesNumericallyEqualValueOfAnyType() {
        DoubleDataValuePredicate predicate = new DoubleDataValuePredicate(2.0d);
        assertTrue(predicate.test(2.0d));
        assertTrue(predicate.test(2L));
        assertTrue(predicate.test(2));
        assertTrue(predicate.test(2.0f));
        assertTrue(predicate.test(BigInteger.TWO));
        assertTrue(predicate.test(new BigDecimal("2.00")));
    }

    @Test
    void doesNotMatchDifferentValue() {
        DoubleDataValuePredicate predicate = new DoubleDataValuePredicate(2.5d);
        assertTrue(predicate.test(2.5d));
        assertFalse(predicate.test(2L));
        assertFalse(predicate.test(2.4d));
    }

    @Test
    void doesNotMatchIntegralOrDecimalValuesThatRoundToTheExpectedDouble() {
        DoubleDataValuePredicate predicate = new DoubleDataValuePredicate(9_007_199_254_740_992d);
        assertTrue(predicate.test(9_007_199_254_740_992L));
        assertTrue(predicate.test(new BigDecimal("9007199254740992")));
        assertFalse(predicate.test(9_007_199_254_740_993L));
        assertFalse(predicate.test(BigInteger.valueOf(9_007_199_254_740_993L)));
        assertFalse(predicate.test(new BigDecimal("9007199254740993")));
    }

    @Test
    void doesNotMatchOtherTypes() {
        DoubleDataValuePredicate predicate = new DoubleDataValuePredicate(2.0d);
        assertFalse(predicate.test("2"));
        assertFalse(predicate.test(Boolean.TRUE));
    }

    @Test
    void doesNotMatchNull() {
        assertFalse(new DoubleDataValuePredicate(2.0d).test(null));
    }
}
