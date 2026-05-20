package org.entur.jwt.spring;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.CachingJWKSetSource;
import com.nimbusds.jose.jwk.source.RefreshAheadCachingJWKSetSource;
import com.nimbusds.jose.util.events.Event;
import com.nimbusds.jose.util.events.EventListener;

import java.util.function.BiConsumer;

/**
 * An {@link EventListener} that forwards JWK-set refresh events for a single issuer to a
 * caller-supplied callback.
 *
 * <p>Handles both {@link CachingJWKSetSource.RefreshCompletedEvent} and
 * {@link RefreshAheadCachingJWKSetSource.ScheduledRefreshCompletedEvent}; other event types
 * are silently ignored.
 */
class IssuerRefreshListener implements EventListener {

    private final String issuer;
    private final BiConsumer<String, JWKSet> onRefresh;

    IssuerRefreshListener(String issuer, BiConsumer<String, JWKSet> onRefresh) {
        this.issuer = issuer;
        this.onRefresh = onRefresh;
    }

    @Override
    public void notify(Event event) {
        if (event instanceof CachingJWKSetSource.RefreshCompletedEvent<?> refreshEvent) {
            onRefresh.accept(issuer, refreshEvent.getJWKSet());
        } else if (event instanceof RefreshAheadCachingJWKSetSource.ScheduledRefreshCompletedEvent<?> scheduledEvent) {
            onRefresh.accept(issuer, scheduledEvent.getJWKSet());
        }
    }
}
