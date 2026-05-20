package org.entur.jwt.spring;

import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.util.Base64URL;

import java.text.ParseException;

public final class JwtHeaderKidExtractor {

    private JwtHeaderKidExtractor() {
    }

    public static String extractKid(String token) {
        if (token == null) {
            return null;
        }

        int firstDot = token.indexOf('.');
        if (firstDot <= 0) {
            return null;
        }

        String headerSegment = token.substring(0, firstDot);
        try {
            JWSHeader jwsHeader = JWSHeader.parse(Base64URL.from(headerSegment));
            return jwsHeader.getKeyID();
        } catch (ParseException e) {
            return null;
        }
    }
}
