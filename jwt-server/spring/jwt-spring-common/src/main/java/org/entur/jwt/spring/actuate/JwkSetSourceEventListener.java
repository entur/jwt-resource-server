package org.entur.jwt.spring.actuate;

import com.nimbusds.jose.jwk.source.OutageTolerantJWKSetSource;
import com.nimbusds.jose.jwk.source.RefreshAheadCachingJWKSetSource;
import com.nimbusds.jose.util.events.Event;
import com.nimbusds.jose.util.events.EventListener;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class JwkSetSourceEventListener implements EventListener {

    private static final Logger LOGGER = LoggerFactory.getLogger(JwkSetSourceEventListener.class);

    protected final String name;

    public JwkSetSourceEventListener(String name) {
        this.name = name;
    }

    @Override
    public void notify(Event event) {

        if(event instanceof OutageTolerantJWKSetSource.OutageEvent outageEvent) {
            LOGGER.warn(name + ": " + OutageTolerantJWKSetSource.OutageEvent.class.getSimpleName() + " with " + (outageEvent.getRemainingTime() / 1000) + "s cache time left");
        } else if(event instanceof RefreshAheadCachingJWKSetSource.UnableToRefreshAheadOfExpirationEvent unableToRefreshAheadOfExpirationEvent) {
            LOGGER.warn(name + ": " + RefreshAheadCachingJWKSetSource.UnableToRefreshAheadOfExpirationEvent.class.getSimpleName());
        } else {
            if(LOGGER.isDebugEnabled()) LOGGER.debug("{}: {}", name, event.getClass().getSimpleName());
        }
    }
}
