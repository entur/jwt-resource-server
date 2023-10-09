package org.entur.jwt.spring;

import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class AudienceOauth2TokenValidator implements OAuth2TokenValidator<Jwt> {

    private final Set<String> audiences;
    private final OAuth2Error error;

    public AudienceOauth2TokenValidator(List<String> audiences) {
        this(new HashSet<>(audiences));
    }

    public AudienceOauth2TokenValidator(Set<String> audiences) {
        this.audiences = audiences;
        this.error = new OAuth2Error("invalid_token", "The audience claim is not valid", "https://tools.ietf.org/html/rfc6750#section-3.1");
    }

    @Override
    public OAuth2TokenValidatorResult validate(Jwt token) {
        List<String> audiences = token.getAudience();
        for (String audience : audiences) {
            if (this.audiences.contains(audience)) {
                return OAuth2TokenValidatorResult.success();
            }
        }
        return OAuth2TokenValidatorResult.failure(error);
    }
}
