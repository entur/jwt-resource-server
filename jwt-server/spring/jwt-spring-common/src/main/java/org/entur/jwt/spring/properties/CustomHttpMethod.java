package org.entur.jwt.spring.properties;

public enum CustomHttpMethod {
    DEFAULT,
    ANT;
    public static CustomHttpMethod fromString(String type) {
        switch (type.toLowerCase()) {
            case "default":
                return DEFAULT;
            case "ant":
                return ANT;
            default:
                throw new IllegalArgumentException("Unknown matcher type '" + type + "'.");
        }
    }
}