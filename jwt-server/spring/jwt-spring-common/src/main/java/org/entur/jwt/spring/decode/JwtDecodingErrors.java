package org.entur.jwt.spring.decode;

import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.util.StringUtils;

import java.util.Collection;

/**
 * Error messages shared by the JWT decoders.
 */
public final class JwtDecodingErrors {

    private static final String DECODING_ERROR_MESSAGE_TEMPLATE = "An error occurred while attempting to decode the Jwt: %s";

    private static final String DEFAULT_VALIDATION_ERROR_MESSAGE = "Unable to validate Jwt";

    private JwtDecodingErrors() {
    }

    public static String decodingErrorMessage(String detail) {
        return String.format(DECODING_ERROR_MESSAGE_TEMPLATE, detail);
    }

    /**
     * @return a message based on the first error with a description, otherwise a generic message
     */
    public static String validationErrorMessage(Collection<OAuth2Error> errors) {
        for (OAuth2Error error : errors) {
            if (StringUtils.hasLength(error.getDescription())) {
                return decodingErrorMessage(error.getDescription());
            }
        }
        return DEFAULT_VALIDATION_ERROR_MESSAGE;
    }
}
