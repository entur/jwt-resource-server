package org.entur.jwt.client;

import java.nio.charset.StandardCharsets;

public class AuthorizationHeaderUtil {

    public static String createHeader(String clientId, String secret) {
        StringBuilder buf = new StringBuilder(clientId);
        buf.append(':').append(secret);

        // encode with padding
        return "Basic " + java.util.Base64.getUrlEncoder().encodeToString(buf.toString().getBytes(StandardCharsets.UTF_8));
    }
}