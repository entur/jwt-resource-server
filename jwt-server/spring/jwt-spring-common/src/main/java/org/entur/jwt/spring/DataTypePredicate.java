package org.entur.jwt.spring;

import java.util.function.Predicate;

public class DataTypePredicate<T> implements Predicate<T> {

    private final Class<T> clazz;

    public DataTypePredicate(Class<T> clazz) {
        this.clazz = clazz;
    }

    @Override
    public boolean test(T t) {
        return t != null && t.getClass().isAssignableFrom(clazz);
    }
}
