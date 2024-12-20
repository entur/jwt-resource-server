package org.entur.jwt.spring.grpc.ecosystem;

import static net.devh.boot.grpc.common.security.SecurityConstants.AUTHORIZATION_HEADER;
import static net.devh.boot.grpc.common.security.SecurityConstants.BEARER_AUTH_PREFIX;

import java.util.function.Function;

import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import net.devh.boot.grpc.server.security.authentication.GrpcAuthenticationReader;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;

import io.grpc.Metadata;
import io.grpc.ServerCall;

/**
 * A version of {@linkplain net.devh.boot.grpc.server.security.authentication.BearerAuthenticationReader} which
 * requires any authentication to be a bearer token type.
 */

public class MustBeBearerIfPresentAuthenticationReader implements GrpcAuthenticationReader {

    private static final String PREFIX = BEARER_AUTH_PREFIX.toLowerCase();
    private static final int PREFIX_LENGTH = PREFIX.length();

    private Function<String, Authentication> tokenWrapper;

    /**
     * Creates a new BearerAuthenticationReader with the given wrapper function.
     * <p>
     * <b>Example-Usage:</b>
     * </p>
     *
     * For spring-security-web:
     *
     * <pre>
     * <code>new BearerAuthenticationReader(token -&gt; new PreAuthenticatedAuthenticationToken(token, null))</code>
     * </pre>
     *
     * For spring-security-oauth2-resource-server:
     *
     * <pre>
     * <code>new BearerAuthenticationReader(token -&gt; new BearerTokenAuthenticationToken(token))</code>
     * </pre>
     * 
     * @param tokenWrapper The function used to convert the token (without bearer prefix) into an {@link Authentication}
     *        object.
     */
    public MustBeBearerIfPresentAuthenticationReader(Function<String, Authentication> tokenWrapper) {
        Assert.notNull(tokenWrapper, "tokenWrapper cannot be null");
        this.tokenWrapper = tokenWrapper;
    }

    @Override
    public Authentication readAuthentication(final ServerCall<?, ?> call, final Metadata headers) {
        final String header = headers.get(AUTHORIZATION_HEADER);

        if (header == null) {
            return null;
        }
        if (!header.toLowerCase().startsWith(PREFIX)) {
            throw new StatusRuntimeException(Status.UNAUTHENTICATED);
        }

        // Cut away the "bearer " prefix
        final String accessToken = header.substring(PREFIX_LENGTH);

        // Not authenticated yet, token needs to be processed
        return tokenWrapper.apply(accessToken);
    }
}
