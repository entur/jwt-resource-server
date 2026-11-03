package org.entur.jwt.spring.properties;

public enum CustomHttpMethod {
    DEFAULT;
    public static CustomHttpMethod fromString(String type) {
        switch (type.toLowerCase()) {
            case "default":
                return DEFAULT;
            default:
                throw new IllegalArgumentException("Unknown matcher type '" + type + "'.");
        }
    }
}