package org.entur.jwt.spring;

import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.util.Assert;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;

public final class JwtExpiresAtValidator implements OAuth2TokenValidator<Jwt> {
    private final Duration clockSkew;
    private Clock clock;

    public JwtExpiresAtValidator(Duration clockSkew) {
        this.clock = Clock.systemUTC();
        Assert.notNull(clockSkew, "clockSkew cannot be null");
        this.clockSkew = clockSkew;
    }

    public OAuth2TokenValidatorResult validate(Jwt jwt) {
        Assert.notNull(jwt, "jwt cannot be null");
        Instant expiry = jwt.getExpiresAt();
        if (expiry != null && Instant.now(this.clock).minus(this.clockSkew).isAfter(expiry)) {
            OAuth2Error oAuth2Error = this.createOAuth2Error(String.format("Jwt expired at %s", jwt.getExpiresAt()));
            return OAuth2TokenValidatorResult.failure(oAuth2Error);
        }
        return OAuth2TokenValidatorResult.success();
    }

    private OAuth2Error createOAuth2Error(String reason) {
        return new OAuth2Error("invalid_token", reason, "https://tools.ietf.org/html/rfc6750#section-3.1");
    }

    public void setClock(Clock clock) {
        Assert.notNull(clock, "clock cannot be null");
        this.clock = clock;
    }

}
