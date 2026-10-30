package org.entur.jwt.spring;

import java.math.BigInteger;
import java.util.function.Predicate;

/**
 * Matches whole numbers of any integral type with the expected value.
 *
 * @see IntegerDataTypePredicate
 */
public class IntegerDataValuePredicate implements Predicate<Object> {

    private final long value;

    public IntegerDataValuePredicate(long value) {
        this.value = value;
    }

    @Override
    public boolean test(Object o) {
        if (o instanceof BigInteger bigInteger) {
            return bigInteger.equals(BigInteger.valueOf(value));
        }
        return IntegerDataTypePredicate.isInteger(o) && ((Number) o).longValue() == value;
    }
}
