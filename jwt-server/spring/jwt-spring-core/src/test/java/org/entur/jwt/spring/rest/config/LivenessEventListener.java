package org.entur.jwt.spring.rest.config;

import org.entur.jwt.spring.JwtAutoConfiguration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.availability.AvailabilityChangeEvent;
import org.springframework.boot.availability.LivenessState;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

@Component
public class LivenessEventListener {
    
    private static Logger log = LoggerFactory.getLogger(LivenessEventListener.class);

    @EventListener
    public void onEvent(AvailabilityChangeEvent<LivenessState> event) {
        log.info("Liveness is " + event.getState());
    }
}