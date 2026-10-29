package org.entur.jwt.spring;

import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.List;

/**
 *
 * The library's JWT validators, by default created from the {@code entur.jwt.claims} configuration
 * (audiences, expiry and not-before leeways and required claims).
 * <br><br>
 * {@link OAuth2TokenValidator} beans are used in addition to these validators. Provide a bean of this type
 * to replace the default validators. Note that the expiry and not-before claims are always validated.
 *
 */

public class EnturJwtValidators {

    private final List<OAuth2TokenValidator<Jwt>> validators;

    public EnturJwtValidators(List<OAuth2TokenValidator<Jwt>> validators) {
        this.validators = validators;
    }

    public List<OAuth2TokenValidator<Jwt>> getValidators() {
        return validators;
    }
}
