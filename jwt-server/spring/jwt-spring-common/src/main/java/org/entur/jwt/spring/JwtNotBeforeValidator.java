package org.entur.jwt.spring;

import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.util.Assert;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;

public final class JwtNotBeforeValidator implements OAuth2TokenValidator<Jwt> {
    private final Duration clockSkew;
    private Clock clock;
    
    public JwtNotBeforeValidator(Duration clockSkew) {
        this.clock = Clock.systemUTC();
        Assert.notNull(clockSkew, "clockSkew cannot be null");
        this.clockSkew = clockSkew;
    }

    public OAuth2TokenValidatorResult validate(Jwt jwt) {
        Assert.notNull(jwt, "jwt cannot be null");

        Instant notBefore = jwt.getNotBefore();
        if (notBefore != null && Instant.now(this.clock).plus(this.clockSkew).isBefore(notBefore)) {
            OAuth2Error oAuth2Error = this.createOAuth2Error(String.format("Jwt used before %s", jwt.getNotBefore()));
            return OAuth2TokenValidatorResult.failure(oAuth2Error);
        } else {
            return OAuth2TokenValidatorResult.success();
        }
    }

    private OAuth2Error createOAuth2Error(String reason) {
        return new OAuth2Error("invalid_token", reason, "https://tools.ietf.org/html/rfc6750#section-3.1");
    }

    public void setClock(Clock clock) {
        Assert.notNull(clock, "clock cannot be null");
        this.clock = clock;
    }

}
