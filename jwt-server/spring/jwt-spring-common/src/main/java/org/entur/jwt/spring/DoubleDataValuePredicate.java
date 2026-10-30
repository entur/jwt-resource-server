package org.entur.jwt.spring;

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
        return o instanceof Number number && number.doubleValue() == value;
    }
}
