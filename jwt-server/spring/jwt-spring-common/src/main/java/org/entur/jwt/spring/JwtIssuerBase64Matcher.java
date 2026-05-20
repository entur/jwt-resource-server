package org.entur.jwt.spring;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.List;

public class JwtIssuerBase64Matcher {

    private final List<EncodedIssuer> issuers;

    public JwtIssuerBase64Matcher(Collection<String> issuers) {
        this.issuers = issuers.stream().map(this::toEncodedIssuer).toList();
    }

    public String matchIssuerFromToken(String token) {
        if (token == null) {
            return null;
        }

        int firstDot = token.indexOf('.');
        if (firstDot <= 0 || firstDot == token.length() - 1) {
            return null;
        }

        int secondDot = token.indexOf('.', firstDot + 1);
        if (secondDot <= firstDot + 1) {
            return null;
        }

        String payloadSegment = token.substring(firstDot + 1, secondDot);
        return matchIssuerFromPayloadSegment(payloadSegment);
    }

    public String matchIssuerFromPayloadSegment(String payloadSegment) {
        String match = null;
        for (EncodedIssuer encodedIssuer : issuers) {
            if (encodedIssuer.matches(payloadSegment)) {
                if (match != null) {
                    return null;
                }
                match = encodedIssuer.issuer();
            }
        }
        return match;
    }

    private EncodedIssuer toEncodedIssuer(String issuer) {
        byte[] bytes = issuer.getBytes(StandardCharsets.UTF_8);
        List<String> encodings = new ArrayList<>(3);
        for (int start = 0; start < 3; start++) {
            int available = bytes.length - start;
            if (available <= 0) {
                continue;
            }
            int length = available - (available % 3);
            if (length <= 0) {
                continue;
            }
            String encoded = Base64.getUrlEncoder().withoutPadding().encodeToString(Arrays.copyOfRange(bytes, start, start + length));
            if (!encoded.isEmpty()) {
                encodings.add(encoded);
            }
        }
        return new EncodedIssuer(issuer, encodings.toArray(new String[0]));
    }

    private record EncodedIssuer(String issuer, String[] encodings) {

        private boolean matches(String payloadSegment) {
            for (String encoding : encodings) {
                if (payloadSegment.contains(encoding)) {
                    return true;
                }
            }
            return false;
        }
    }
}
