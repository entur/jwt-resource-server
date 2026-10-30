package org.entur.jwt.spring;

import java.math.BigInteger;
import java.util.function.Predicate;

/**
 * Matches whole numbers of any integral type. Nimbus parses JSON whole numbers to {@link Long},
 * but other sources of claims might use for example {@link Integer}.
 */
public class IntegerDataTypePredicate implements Predicate<Object> {

    public static boolean isInteger(Object o) {
        return o instanceof Long || o instanceof Integer || o instanceof Short || o instanceof Byte || o instanceof BigInteger;
    }

    @Override
    public boolean test(Object o) {
        return isInteger(o);
    }
}
