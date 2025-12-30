package org.entur.jwt.spring;

import org.entur.jwt.spring.properties.jwk.JwtClaimConstraintProperties;
import org.entur.jwt.spring.properties.jwk.JwtClaimsProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimValidator;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Predicate;

public class OAuth2TokenValidatorFactory {

    private static final Logger LOGGER = LoggerFactory.getLogger(JwtAutoConfiguration.class);

    public List<OAuth2TokenValidator<Jwt>> create(JwtClaimsProperties claims) {
        List<OAuth2TokenValidator<Jwt>> claimValidators = new ArrayList<>();

        List<String> audiences = claims.getAudiences();
        if (!audiences.isEmpty()) {
            claimValidators.add(new AudienceOauth2TokenValidator(audiences));
        }

        claimValidators.add(new JwtExpiresAtValidator(Duration.ofSeconds(claims.getExpiresAtLeeway())));
        claimValidators.add(new JwtNotBeforeValidator(Duration.ofSeconds(claims.getIssuedAtLeeway())));

        List<JwtClaimConstraintProperties> valueConstraints = getValueConstraints(claims);
        for (JwtClaimConstraintProperties valueConstraint : valueConstraints) {
            claimValidators.add(toValueConstraint(valueConstraint));
        }

        List<JwtClaimConstraintProperties> dataTypeConstraints = getDataTypeConstraints(claims);
        for (JwtClaimConstraintProperties dataTypeConstraint : dataTypeConstraints) {
            claimValidators.add(toTypeConstraint(dataTypeConstraint));
        }

        return claimValidators;
    }

    private <T> JwtClaimValidator<T> toTypeConstraint(JwtClaimConstraintProperties dataTypeConstraint) {
        Class<?> typeClass = getTypeClass(dataTypeConstraint.getType());

        Predicate<T> predicate = (Predicate<T>) new DataTypePredicate<>(typeClass);
        return new JwtClaimValidator<>(dataTypeConstraint.getName(), predicate);
    }

    private Class<?> getTypeClass(String type) {
        switch (type) {
            case "integer": {
                // TODO long vs int
                return Long.class;
            }
            case "boolean": {
                return Boolean.class;
            }
            case "string": {
                return String.class;
            }
            case "double": {
                return Double.class;
            }
            default: {
                throw new IllegalArgumentException("Unexpected claim type '" + type + "'");
            }
        }
    }

    private <T> JwtClaimValidator<T> toValueConstraint(JwtClaimConstraintProperties r) {
        Predicate<T> predicate = toDataValuePredicate(r);

        return new JwtClaimValidator<>(r.getName(), predicate);
    }

    private <T> Predicate<T> toDataValuePredicate(JwtClaimConstraintProperties r) {

        switch (r.getType()) {
            case "integer": {

                // TODO long vs int
                /*
                Long l = Long.parseLong(r.getValue());
                if (l <= Integer.MAX_VALUE) {
                    jwtBuilder.withClaim(r.getName(), l.intValue());
                } else {
                    jwtBuilder.withClaim(r.getName(), l);
                }
                 */
                return (Predicate<T>) new DataValuePredicate<>(Long.parseLong(r.getValue()));
            }
            case "boolean": {
                return (Predicate<T>) new DataValuePredicate<>(Boolean.parseBoolean(r.getValue()));
            }
            case "string": {
                return (Predicate<T>) new DataValuePredicate<>(r.getValue());
            }
            case "double": {
                return (Predicate<T>) new DataValuePredicate<>(Double.parseDouble(r.getValue()));
            }
            default: {
                throw new IllegalArgumentException("Unexpected claim type '" + r.getType() + "'");
            }
        }

    }

    public List<JwtClaimConstraintProperties> getValueConstraints(JwtClaimsProperties claims) {
        List<JwtClaimConstraintProperties> dataValueConstraints = new ArrayList<>();
        for (JwtClaimConstraintProperties r : claims.getRequire()) {
            if (r.getValue() != null) {
                if(LOGGER.isInfoEnabled()) LOGGER.info("Require claim {} of type {}", r.getName(), r.getType());

                dataValueConstraints.add(r);
            }
        }
        return dataValueConstraints;
    }

    protected List<JwtClaimConstraintProperties> getDataTypeConstraints(JwtClaimsProperties claims) {
        List<JwtClaimConstraintProperties> dataTypeConstraints = new ArrayList<>();
        for (JwtClaimConstraintProperties r : claims.getRequire()) {
            if (r.getValue() == null) {
                if(LOGGER.isInfoEnabled()) LOGGER.info("Require claim {} value {} of type {}", r.getName(), r.getValue(), r.getType());

                dataTypeConstraints.add(r);
            }
        }
        return dataTypeConstraints;
    }
}
