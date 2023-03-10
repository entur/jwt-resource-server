package org.entur.jwt.spring.actuate;

import com.nimbusds.jose.util.events.Event;
import com.nimbusds.jose.util.events.EventListener;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class JwkSetSourceEventListener implements EventListener {

    private static final Logger LOGGER = LoggerFactory.getLogger(JwkSetSourceEventListener.class);

    @Override
    public void notify(Event event) {
        LOGGER.info(event.getClass().getName());
    }
}
