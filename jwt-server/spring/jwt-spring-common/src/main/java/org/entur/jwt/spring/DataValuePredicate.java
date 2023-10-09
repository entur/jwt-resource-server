package org.entur.jwt.spring;

import java.util.function.Predicate;

public class DataValuePredicate<T> implements Predicate<T> {

    private final T value;

    public DataValuePredicate(T value) {
        this.value = value;
    }

    @Override
    public boolean test(T t) {
        return t != null && value.equals(t);
    }
}
