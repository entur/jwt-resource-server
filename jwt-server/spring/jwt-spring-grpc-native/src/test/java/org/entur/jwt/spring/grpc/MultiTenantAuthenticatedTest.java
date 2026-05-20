package org.entur.jwt.spring.grpc;

import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import org.entur.jwt.junit5.AccessToken;
import org.entur.jwt.junit5.AuthorizationServer;
import org.entur.jwt.junit5.claim.Issuer;
import org.entur.jwt.junit5.sabotage.Signature;
import org.entur.jwt.spring.grpc.test.GreetingResponse;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.test.annotation.DirtiesContext;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Multi-tenant integration tests for the {@code IssuerJwtDecoder} fast-path
 * issuer resolution, exercising the JWK event listener-driven KID uniqueness
 * detection and header-to-issuer cache.
 *
 * <p>Verifies that:
 * <ul>
 *   <li>Tokens from either configured issuer are accepted (slow path and
 *       subsequent fast path).</li>
 *   <li>Tokens with an invalid signature are rejected.</li>
 *   <li>Tokens whose issuer does not match any configured tenant are rejected.</li>
 * </ul>
 */
@AuthorizationServer("partner")
@AuthorizationServer("internal")
@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
@DirtiesContext
public class MultiTenantAuthenticatedTest extends AbstractGrpcTest {

    // ------------------------------------------------------------------ slow path (first request per issuer)

    @Test
    public void testProtectedResourceWithPartnerToken(@AccessToken(by = "partner", audience = "https://my.audience") String token) {
        GreetingResponse response = stub(token).protectedWithPartnerTenant(greetingRequest);
        assertThat(response.getMessage()).isEqualTo("Hello protected tenant");
    }

    @Test
    public void testProtectedResourceWithInternalToken(@AccessToken(by = "internal", audience = "https://my.audience") String token) {
        GreetingResponse response = stub(token).protectedWithPartnerTenant(greetingRequest);
        assertThat(response.getMessage()).isEqualTo("Hello protected tenant");
    }

    // ------------------------------------------------------------------ fast path (second request, same issuer header)

    @Test
    public void testFastPathAfterCacheWarm(
            @AccessToken(by = "partner", audience = "https://my.audience") String partnerToken,
            @AccessToken(by = "internal", audience = "https://my.audience") String internalToken) {

        // Warm the cache for both issuers via the slow path
        assertThat(stub(partnerToken).protectedWithPartnerTenant(greetingRequest).getMessage())
                .isEqualTo("Hello protected tenant");
        assertThat(stub(internalToken).protectedWithPartnerTenant(greetingRequest).getMessage())
                .isEqualTo("Hello protected tenant");

        // Subsequent requests from the same issuers should succeed via the fast path
        assertThat(stub(partnerToken).protectedWithPartnerTenant(greetingRequest).getMessage())
                .isEqualTo("Hello protected tenant");
        assertThat(stub(internalToken).protectedWithPartnerTenant(greetingRequest).getMessage())
                .isEqualTo("Hello protected tenant");
    }

    // ------------------------------------------------------------------ negative cases

    @Test
    public void testPartnerTokenWithInvalidSignatureIsRejected(
            @AccessToken(by = "partner", audience = "https://my.audience") @Signature("tampered") String token) {
        StatusRuntimeException exception = assertThrows(StatusRuntimeException.class, () ->
                stub(token).protectedWithPartnerTenant(greetingRequest));
        assertThat(exception.getStatus().getCode()).isEqualTo(Status.Code.UNAUTHENTICATED);
    }

    @Test
    public void testTokenWithUnknownIssuerIsRejected(
            @AccessToken(by = "partner", audience = "https://my.audience") @Issuer("https://unknown.issuer.example") String token) {
        StatusRuntimeException exception = assertThrows(StatusRuntimeException.class, () ->
                stub(token).protectedWithPartnerTenant(greetingRequest));
        assertThat(exception.getStatus().getCode()).isEqualTo(Status.Code.UNAUTHENTICATED);
    }
}
