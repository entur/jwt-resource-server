package org.entur.jwt.spring;

import org.entur.jwt.spring.auth0.properties.jwk.JwtClaimConstraintProperties;
import org.entur.jwt.spring.auth0.properties.jwk.JwtClaimsProperties;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class DataTypeClaimOauth2TokenValidatorFactory {


    private void addValueConstraints(Verification jwtBuilder, List<JwtClaimConstraintProperties> valueConstraints) {
        for (JwtClaimConstraintProperties r : valueConstraints) {
            switch (r.getType()) {
                case "integer": {
                    add(jwtBuilder, r);
                    break;
                }
                case "boolean": {
                    jwtBuilder.withClaim(r.getName(), Boolean.parseBoolean(r.getValue()));
                    break;
                }
                case "string": {
                    jwtBuilder.withClaim(r.getName(), r.getValue());
                    break;
                }
                case "double": {
                    jwtBuilder.withClaim(r.getName(), Double.parseDouble(r.getValue()));
                    break;
                }
                default: {
                    throw new IllegalArgumentException("Unexpected claim type '" + r.getType() + "'");
                }
            }
        }
    }

    private ClaimOauth2TokenValidator getVerifierForDataTypes(List<JwtClaimConstraintProperties> dataTypeConstraints) {
        // add claim-verifying wrapper
        Map<String, Class<?>> types = new HashMap<>(dataTypeConstraints.size() * 2);

        for (JwtClaimConstraintProperties r : dataTypeConstraints) {
            switch (r.getType()) {
                case "integer": {
                    types.put(r.getName(), Long.class); // integers can be cast to long, so should not be a problem.
                    break;
                }
                case "boolean": {
                    types.put(r.getName(), Boolean.class);
                    break;
                }
                case "string": {
                    types.put(r.getName(), String.class);
                    break;
                }
                case "double": {
                    types.put(r.getName(), Double.class);
                    break;
                }
                default: {
                    throw new IllegalArgumentException("Unexpected claim type '" + r.getType() + "'");
                }
            }
        }

        return new JwtClaimVerifier<>(verifier, extractor, types, Collections.emptyMap());
    }

    private void add(Verification jwtBuilder, JwtClaimConstraintProperties r) {
        Long l = Long.parseLong(r.getValue());
        if (l <= Integer.MAX_VALUE) {
            jwtBuilder.withClaim(r.getName(), l.intValue());
        } else {
            jwtBuilder.withClaim(r.getName(), l);
        }
    }

    public List<JwtClaimConstraintProperties> getValueConstraints(JwtClaimsProperties claims) {
        List<JwtClaimConstraintProperties> dataValueConstraints = new ArrayList<>();
        for (JwtClaimConstraintProperties r : claims.getRequire()) {
            if (r.getValue() != null) {
                log.info("Require claim {} of type {}", r.getName(), r.getType());

                dataValueConstraints.add(r);
            }
        }
        return dataValueConstraints;
    }

    public List<JwtClaimConstraintProperties> getDataTypeConstraints(JwtClaimsProperties claims) {
        List<JwtClaimConstraintProperties> dataTypeConstraints = new ArrayList<>();
        for (JwtClaimConstraintProperties r : claims.getRequire()) {
            if (r.getValue() == null) {
                log.info("Require claim {} value {} of type {}", r.getName(), r.getValue(), r.getType());

                dataTypeConstraints.add(r);
            }
        }
        return dataTypeConstraints;
    }
}
