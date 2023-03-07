package org.entur.jwt.spring;

import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class DataTypesClaimOauth2TokenValidator implements OAuth2TokenValidator<Jwt> {

    private final Map<String, Class<?>> types;

    public DataTypesClaimOauth2TokenValidator(Map<String, Class<?>> types) {
        this.types = types;
    }

    @Override
    public OAuth2TokenValidatorResult validate(Jwt token) {
        List<OAuth2Error> errors = null;

        Map<String, Object> claims = token.getClaims();

        for (Map.Entry<String, Class<?>> stringClassEntry : types.entrySet()) {
            Object o = claims.get(stringClassEntry.getKey());

            if (o == null || !o.getClass().isAssignableFrom(stringClassEntry.getValue())) {
                if (errors == null) {
                    errors = new ArrayList<>();

                    OAuth2Error error = new OAuth2Error("invalid_token", "The " + stringClassEntry.getKey() + " claim is " + (o == null ? "required" : "invalid"), "https://tools.ietf.org/html/rfc6750#section-3.1");
                    errors.add(error);
                }
            }
        }

        if (errors != null) {
            return OAuth2TokenValidatorResult.failure(errors);
        }

        return OAuth2TokenValidatorResult.success();
    }
}
