package org.entur.jwt.spring.decode;

import org.entur.jwt.spring.EnturJwtValidators;
import org.entur.jwt.spring.JwtExpiresAtValidator;
import org.entur.jwt.spring.JwtNotBeforeValidator;
import org.entur.jwt.spring.properties.jwk.JwtClaimsProperties;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtIssuerValidator;
import org.springframework.security.oauth2.jwt.JwtTimestampValidator;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

/**
 * JWT validators of the per-issuer decoders, shared by the web, gRPC and webflux modules.
 */
public final class JwtDecoderValidators {

    // same as the default clock skew of Spring Security (and Nimbus)
    public static final Duration DEFAULT_LEEWAY = Duration.ofSeconds(60);

    private JwtDecoderValidators() {
    }

    /**
     * Combine the library validators with additional validators (i.e. {@link OAuth2TokenValidator} beans), so that the
     * additional validators do not replace the library validators.
     *
     * @param enturJwtValidators the library validators
     * @param additionalValidators additional validators
     * @param claims leeways for validating the expiry and not-before claims, if the library validators do not (i.e. have been replaced)
     * @return the combined validators
     */
    public static List<OAuth2TokenValidator<Jwt>> combine(EnturJwtValidators enturJwtValidators, Stream<OAuth2TokenValidator<Jwt>> additionalValidators, JwtClaimsProperties claims) {
        List<OAuth2TokenValidator<Jwt>> validators = new ArrayList<>(enturJwtValidators.getValidators());
        additionalValidators.forEach(validators::add);
        return withTimestampValidators(validators, Duration.ofSeconds(claims.getExpiresAtLeeway()), Duration.ofSeconds(claims.getIssuedAtLeeway()));
    }

    /**
     * @param issuer the issuer
     * @param jwtValidators the validators
     * @return validator for the decoder of a single issuer, which also always validates the expiry and not-before claims
     */
    public static DelegatingOAuth2TokenValidator<Jwt> create(String issuer, List<OAuth2TokenValidator<Jwt>> jwtValidators) {
        List<OAuth2TokenValidator<Jwt>> validators = new ArrayList<>();
        validators.add(new JwtIssuerValidator(issuer));
        validators.addAll(jwtValidators);
        return new DelegatingOAuth2TokenValidator<>(withTimestampValidators(validators, DEFAULT_LEEWAY, DEFAULT_LEEWAY));
    }

    /**
     * The JWT processors do not check the expiry and not-before claims, so make sure they are always validated
     * (for example if the library validators have been replaced).
     *
     * @return the validators, plus expiry and/or not-before validators with the given leeways if missing
     */
    public static List<OAuth2TokenValidator<Jwt>> withTimestampValidators(List<OAuth2TokenValidator<Jwt>> jwtValidators, Duration expiresAtLeeway, Duration notBeforeLeeway) {
        List<OAuth2TokenValidator<Jwt>> validators = new ArrayList<>(jwtValidators);
        if (validators.stream().noneMatch(v -> v instanceof JwtExpiresAtValidator || v instanceof JwtTimestampValidator)) {
            validators.add(new JwtExpiresAtValidator(expiresAtLeeway));
        }
        if (validators.stream().noneMatch(v -> v instanceof JwtNotBeforeValidator || v instanceof JwtTimestampValidator)) {
            validators.add(new JwtNotBeforeValidator(notBeforeLeeway));
        }
        return validators;
    }
}
