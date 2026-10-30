package org.entur.jwt.spring;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.function.Predicate;

/**
 * Matches numbers of any type which are numerically equal to the expected value. Nimbus parses
 * JSON whole numbers to {@link Long}, so for example {@code 2} must match the expected value {@code 2.0}.
 */
public class DoubleDataValuePredicate implements Predicate<Object> {

    private final double value;

    public DoubleDataValuePredicate(double value) {
        this.value = value;
    }

    @Override
    public boolean test(Object o) {
        if (!(o instanceof Number number)) {
            return false;
        }
        if (number instanceof BigDecimal decimal) {
            return Double.isFinite(value) && decimal.compareTo(
                    value == Math.rint(value) ? BigDecimal.valueOf(value) : BigDecimal.valueOf(value)) == 0;
        }
        if (number instanceof BigInteger integer) {
            return Double.isFinite(value) && new BigDecimal(integer).compareTo(BigDecimal.valueOf(value)) == 0;
        }
        if (number instanceof Byte || number instanceof Short || number instanceof Integer || number instanceof Long) {
            return Double.isFinite(value) && BigDecimal.valueOf(number.longValue()).compareTo(BigDecimal.valueOf(value)) == 0;
        }
        return number.doubleValue() == value;
    }
}
