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
        Predicate<T> predicate = (Predicate<T>) toDataTypePredicate(dataTypeConstraint.getType());

        return new JwtClaimValidator<>(dataTypeConstraint.getName(), predicate);
    }

    private Predicate<?> toDataTypePredicate(String type) {
        switch (type) {
            case "integer": {
                // Nimbus parses JSON whole numbers to Long, but accept any integral type
                return new IntegerDataTypePredicate();
            }
            case "boolean": {
                return new DataTypePredicate<>(Boolean.class);
            }
            case "string": {
                return new DataTypePredicate<>(String.class);
            }
            case "double": {
                // any number, as Nimbus parses JSON whole numbers (i.e. 1) to Long
                return new DataTypePredicate<>(Number.class);
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
                // compare numerically, regardless of the integral type
                return (Predicate<T>) new IntegerDataValuePredicate(Long.parseLong(r.getValue()));
            }
            case "boolean": {
                return (Predicate<T>) new DataValuePredicate<>(Boolean.parseBoolean(r.getValue()));
            }
            case "string": {
                return (Predicate<T>) new DataValuePredicate<>(r.getValue());
            }
            case "double": {
                // compare numerically, as Nimbus parses JSON whole numbers (i.e. 2) to Long
                return (Predicate<T>) new DoubleDataValuePredicate(Double.parseDouble(r.getValue()));
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
