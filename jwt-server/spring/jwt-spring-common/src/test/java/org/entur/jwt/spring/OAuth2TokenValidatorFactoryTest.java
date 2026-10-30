package org.entur.jwt.spring;

import com.nimbusds.jwt.JWTClaimsSet;
import org.entur.jwt.spring.properties.jwk.JwtClaimConstraintProperties;
import org.entur.jwt.spring.properties.jwk.JwtClaimsProperties;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;

import java.math.BigInteger;
import java.text.ParseException;
import java.time.Instant;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Required claims (type and value) for claims as parsed by Nimbus, which parses JSON whole numbers to {@link Long}
 * and other numbers to {@link Double}.
 */
class OAuth2TokenValidatorFactoryTest {

    @Test
    void testDoubleTypeAcceptsAnyNumber() throws ParseException {
        OAuth2TokenValidator<Jwt> validator = validator("ratio", "double", null);

        assertValid(validator, parse("{\"ratio\": 1}"));
        assertValid(validator, parse("{\"ratio\": 1.5}"));
        assertValid(validator, parse("{\"ratio\": 1.0}"));
        assertValid(validator, parse("{\"ratio\": -2}"));
        assertValid(validator, parse("{\"ratio\": 1e3}"));
        assertValid(validator, jwt(Map.of("ratio", 1)));
    }

    @Test
    void testDoubleTypeRejectsNonNumbers() throws ParseException {
        OAuth2TokenValidator<Jwt> validator = validator("ratio", "double", null);

        assertInvalid(validator, parse("{\"ratio\": \"1.5\"}"));
        assertInvalid(validator, parse("{\"ratio\": true}"));
        assertInvalid(validator, parse("{\"ratio\": [1.5]}"));
        assertInvalid(validator, parse("{\"other\": 1.5}"));
    }

    @Test
    void testDoubleValueComparesNumerically() throws ParseException {
        OAuth2TokenValidator<Jwt> validator = validator("level", "double", "2");

        assertValid(validator, parse("{\"level\": 2}"));
        assertValid(validator, parse("{\"level\": 2.0}"));
        assertValid(validator, parse("{\"level\": 2e0}"));
        assertValid(validator, jwt(Map.of("level", 2)));

        assertInvalid(validator, parse("{\"level\": 2.5}"));
        assertInvalid(validator, parse("{\"level\": 3}"));
        assertInvalid(validator, parse("{\"level\": \"2\"}"));
        assertInvalid(validator, parse("{\"other\": 2}"));
    }

    @Test
    void testDoubleValueWithFraction() throws ParseException {
        OAuth2TokenValidator<Jwt> validator = validator("level", "double", "2.5");

        assertValid(validator, parse("{\"level\": 2.5}"));
        assertValid(validator, parse("{\"level\": 2.50}"));

        assertInvalid(validator, parse("{\"level\": 2}"));
        assertInvalid(validator, parse("{\"level\": 3}"));
    }

    @Test
    void testIntegerTypeAcceptsAnyIntegralType() throws ParseException {
        OAuth2TokenValidator<Jwt> validator = validator("count", "integer", null);

        assertValid(validator, parse("{\"count\": 1}"));
        assertValid(validator, parse("{\"count\": -1}"));
        assertValid(validator, parse("{\"count\": 9223372036854775807}"));
        assertValid(validator, jwt(Map.of("count", 1)));
        assertValid(validator, jwt(Map.of("count", (short) 1)));
        assertValid(validator, jwt(Map.of("count", (byte) 1)));
        assertValid(validator, jwt(Map.of("count", BigInteger.ONE)));
    }

    @Test
    void testIntegerTypeRejectsOtherTypes() throws ParseException {
        OAuth2TokenValidator<Jwt> validator = validator("count", "integer", null);

        assertInvalid(validator, parse("{\"count\": 1.5}"));
        // parsed to Double
        assertInvalid(validator, parse("{\"count\": 1.0}"));
        assertInvalid(validator, parse("{\"count\": \"1\"}"));
        assertInvalid(validator, parse("{\"count\": true}"));
        assertInvalid(validator, parse("{\"other\": 1}"));
    }

    @Test
    void testIntegerValueComparesNumerically() throws ParseException {
        OAuth2TokenValidator<Jwt> validator = validator("count", "integer", "2");

        assertValid(validator, parse("{\"count\": 2}"));
        assertValid(validator, jwt(Map.of("count", 2)));
        assertValid(validator, jwt(Map.of("count", (short) 2)));
        assertValid(validator, jwt(Map.of("count", BigInteger.TWO)));

        assertInvalid(validator, parse("{\"count\": 3}"));
        assertInvalid(validator, parse("{\"count\": 2.0}"));
        assertInvalid(validator, parse("{\"count\": \"2\"}"));
        assertInvalid(validator, parse("{\"other\": 2}"));
        assertInvalid(validator, jwt(Map.of("count", BigInteger.TWO.add(BigInteger.ONE.shiftLeft(64)))));
    }

    @Test
    void testIntegerValueBeyondIntegerRange() throws ParseException {
        OAuth2TokenValidator<Jwt> validator = validator("count", "integer", "9223372036854775807");

        assertValid(validator, parse("{\"count\": 9223372036854775807}"));
        assertInvalid(validator, parse("{\"count\": 9223372036854775806}"));
    }

    @Test
    void testBooleanAndString() throws ParseException {
        assertValid(validator("admin", "boolean", null), parse("{\"admin\": false}"));
        assertInvalid(validator("admin", "boolean", null), parse("{\"admin\": \"false\"}"));
        assertValid(validator("admin", "boolean", "true"), parse("{\"admin\": true}"));
        assertInvalid(validator("admin", "boolean", "true"), parse("{\"admin\": false}"));

        assertValid(validator("tenant", "string", null), parse("{\"tenant\": \"a\"}"));
        assertInvalid(validator("tenant", "string", null), parse("{\"tenant\": 1}"));
        assertValid(validator("tenant", "string", "a"), parse("{\"tenant\": \"a\"}"));
        assertInvalid(validator("tenant", "string", "a"), parse("{\"tenant\": \"b\"}"));
    }

    @Test
    void testUnexpectedType() {
        assertThatThrownBy(() -> validator("count", "long", null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("'long'");
        assertThatThrownBy(() -> validator("count", "long", "1"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("'long'");
    }

    private static OAuth2TokenValidator<Jwt> validator(String name, String type, String value) {
        JwtClaimConstraintProperties constraint = new JwtClaimConstraintProperties();
        constraint.setName(name);
        constraint.setType(type);
        constraint.setValue(value);

        JwtClaimsProperties claims = new JwtClaimsProperties();
        claims.getRequire().add(constraint);

        return new DelegatingOAuth2TokenValidator<>(new OAuth2TokenValidatorFactory().create(claims));
    }

    /**
     * Parse the claims like the JWT decoders do.
     */
    private static Jwt parse(String claims) throws ParseException {
        return jwt(JWTClaimsSet.parse(claims).getClaims());
    }

    private static Jwt jwt(Map<String, Object> claims) {
        Instant now = Instant.now();
        return Jwt.withTokenValue("token")
                .header("alg", "none")
                .claims(c -> c.putAll(claims))
                .issuedAt(now)
                .expiresAt(now.plusSeconds(60))
                .build();
    }

    private static void assertValid(OAuth2TokenValidator<Jwt> validator, Jwt jwt) {
        assertThat(validator.validate(jwt).getErrors()).as("errors for claims %s", jwt.getClaims()).isEmpty();
    }

    private static void assertInvalid(OAuth2TokenValidator<Jwt> validator, Jwt jwt) {
        assertThat(validator.validate(jwt).hasErrors()).as("errors for claims %s", jwt.getClaims()).isTrue();
    }
}
