package org.entur.jwt.client;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class AuthorizationHeaderUtil {

    /**
     * Create a Basic authorization header for client authentication, encoded like Spring Security does: the client id
     * and secret are form url-encoded (RFC 6749 section 2.3.1), then Base64 encoded (RFC 7617).
     *
     * @param clientId client id
     * @param secret client secret
     * @return authorization header value
     */

    public static String createHeader(String clientId, String secret) {
        StringBuilder buf = new StringBuilder(encode(clientId));
        buf.append(':').append(encode(secret));

        // basic authentication uses the standard (not url-safe) alphabet, with padding
        return "Basic " + Base64.getEncoder().encodeToString(buf.toString().getBytes(StandardCharsets.UTF_8));
    }

    private static String encode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }
}
