package org.entur.jwt.spring;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.util.events.EventListener;

import java.util.function.BiConsumer;

/**
 * Per-issuer context that binds an issuer string to an {@link IssuerRefreshListener} and
 * tracks the most-recently-seen {@link JWKSet} for that issuer.
 *
 * <p>When a JWK-set refresh event arrives via {@link #getEventListener()}:
 * <ol>
 *   <li>The {@link JWKSet} snapshot is stored in {@link #getCurrentJwkSet()}.</li>
 *   <li>The kid-cache callback ({@code kidCacheCallback}) is invoked, keeping the
 *       {@link JwtKidIssuerCache} up to date.</li>
 *   <li>The manager-update callback ({@code managerCallback}) is invoked, allowing callers
 *       to rebuild and replace the per-issuer authentication manager.</li>
 * </ol>
 *
 * <p>Register {@link #getEventListener()} with the issuer's JWK event bus (e.g. via
 * {@link org.entur.jwt.spring.actuate.ListEventListener#addEventListener}).
 */
public class IssuerJwkContext {

    private final String issuer;
    private final IssuerRefreshListener issuerRefreshListener;
    private volatile JWKSet currentJwkSet;

    /**
     * @param issuer            the issuer URL this context belongs to
     * @param kidCacheCallback  called with {@code (issuer, jwkSet)} to update the kid→issuer cache
     * @param managerCallback   called with {@code (issuer, jwkSet)} to update the authentication manager
     */
    public IssuerJwkContext(String issuer,
                            BiConsumer<String, JWKSet> kidCacheCallback,
                            BiConsumer<String, JWKSet> managerCallback) {
        this.issuer = issuer;
        this.issuerRefreshListener = new IssuerRefreshListener(issuer, (iss, jwkSet) -> {
            this.currentJwkSet = jwkSet;
            kidCacheCallback.accept(iss, jwkSet);
            managerCallback.accept(iss, jwkSet);
        });
    }

    /** Returns the issuer URL this context belongs to. */
    public String getIssuer() {
        return issuer;
    }

    /**
     * Returns the {@link EventListener} to register with the issuer's JWK event bus.
     * This is the {@link IssuerRefreshListener} created at construction time.
     */
    public EventListener getEventListener() {
        return issuerRefreshListener;
    }

    /**
     * Returns the most-recently-received {@link JWKSet} for this issuer, or {@code null}
     * if no JWK-set refresh event has been received yet.
     */
    public JWKSet getCurrentJwkSet() {
        return currentJwkSet;
    }
}
