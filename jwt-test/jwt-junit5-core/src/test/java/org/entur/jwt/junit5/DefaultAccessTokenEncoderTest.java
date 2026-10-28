package org.entur.jwt.junit5;

import com.google.common.collect.Range;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import org.entur.jwt.junit5.claim.Audience;
import org.entur.jwt.junit5.claim.ExpiresAt;
import org.entur.jwt.junit5.claim.IssuedAt;
import org.entur.jwt.junit5.claim.JsonClaim;
import org.entur.jwt.junit5.claim.MapClaim;
import org.entur.jwt.junit5.claim.MissingClaim;
import org.entur.jwt.junit5.claim.Scope;
import org.junit.jupiter.api.Test;

import java.text.ParseException;
import java.util.Date;
import java.util.List;
import java.util.Map;

import static com.google.common.truth.Truth.assertThat;

@AuthorizationServer
public class DefaultAccessTokenEncoderTest {

    private static JWTClaimsSet decode(String token) throws ParseException {
        return JWTParser.parse(token.substring(7)).getJWTClaimsSet();
    }

    private static long now() {
        return System.currentTimeMillis() / 1000;
    }

    private static long seconds(Date date) {
        return date.getTime() / 1000;
    }

    @Test
    public void testDefaultExpiresAtAndIssuedAtInSeconds(@AccessToken String token) throws ParseException {
        JWTClaimsSet claims = decode(token);

        // default is 10 minutes
        assertThat(seconds(claims.getExpirationTime())).isIn(Range.closed(now() + 10 * 60 - 5, now() + 10 * 60));
        assertThat(seconds(claims.getIssueTime())).isIn(Range.closed(now() - 5, now()));
    }

    @Test
    public void testAccessTokenExpiresAtAndIssuedAtInSeconds(@AccessToken(issuedAt = -30, expiresAt = 60) String token) throws ParseException {
        JWTClaimsSet claims = decode(token);

        assertThat(seconds(claims.getExpirationTime())).isIn(Range.closed(now() + 60 - 5, now() + 60));
        assertThat(seconds(claims.getIssueTime())).isIn(Range.closed(now() - 30 - 5, now() - 30));
    }

    @Test
    public void testExpiresAtAndIssuedAtAnnotationsInSeconds(@AccessToken @IssuedAt(-30) @ExpiresAt(60) String token) throws ParseException {
        JWTClaimsSet claims = decode(token);

        assertThat(seconds(claims.getExpirationTime())).isIn(Range.closed(now() + 60 - 5, now() + 60));
        assertThat(seconds(claims.getIssueTime())).isIn(Range.closed(now() - 30 - 5, now() - 30));
    }

    @Test
    public void testMissingExpiresAt(@AccessToken @MissingClaim("exp") String token) throws ParseException {
        JWTClaimsSet claims = decode(token);

        assertThat(claims.getExpirationTime()).isNull();
        assertThat(claims.getIssueTime()).isNotNull();
    }

    @Test
    public void testMissingIssuedAt(@AccessToken @MissingClaim("iat") String token) throws ParseException {
        JWTClaimsSet claims = decode(token);

        assertThat(claims.getIssueTime()).isNull();
        assertThat(claims.getExpirationTime()).isNotNull();
    }

    @Test
    public void testJsonClaim(@AccessToken @JsonClaim(name = "myJson", value = "{\"a\":1,\"b\":[\"c\",\"d\"]}") String token) throws ParseException {
        JWTClaimsSet claims = decode(token);

        Map<String, Object> json = claims.getJSONObjectClaim("myJson");
        assertThat(((Number) json.get("a")).intValue()).isEqualTo(1);
        assertThat((List<?>) json.get("b")).containsExactly("c", "d").inOrder();
    }

    @Test
    public void testRepeatedAudience(@AccessToken @Audience("a") @Audience({"b", "c"}) String token) throws ParseException {
        JWTClaimsSet claims = decode(token);

        assertThat(claims.getAudience()).containsExactly("a", "b", "c").inOrder();
    }

    @Test
    public void testAudienceOverridesAccessToken(@AccessToken(audience = "x") @Audience("a") String token) throws ParseException {
        JWTClaimsSet claims = decode(token);

        assertThat(claims.getAudience()).containsExactly("a");
    }

    @Test
    public void testRepeatedScope(@AccessToken @Scope("read") @Scope({"write", "delete"}) String token) throws ParseException {
        JWTClaimsSet claims = decode(token);

        assertThat(claims.getStringClaim("scope")).isEqualTo("read write delete");
    }

    @Test
    public void testAccessTokenScopeIsSpaceDelimited(@AccessToken(scope = {"read", "write"}) String token) throws ParseException {
        JWTClaimsSet claims = decode(token);

        assertThat(claims.getStringClaim("scope")).isEqualTo("read write");
    }

    @Test
    public void testMapClaimAtRoot(@AccessToken @MapClaim(path = {}, entries = @MapClaim.Entry(name = "myRootClaim", value = "myValue")) String token) throws ParseException {
        JWTClaimsSet claims = decode(token);

        assertThat(claims.getStringClaim("myRootClaim")).isEqualTo("myValue");
    }

    @Test
    public void testMapClaimAtPath(@AccessToken @MapClaim(path = {"a", "b"}, entries = @MapClaim.Entry(name = "c", type = Integer.class, value = "1")) String token) throws ParseException {
        JWTClaimsSet claims = decode(token);

        Map<String, Object> a = claims.getJSONObjectClaim("a");
        Map<?, ?> b = (Map<?, ?>) a.get("b");
        assertThat(((Number) b.get("c")).intValue()).isEqualTo(1);
    }
}
