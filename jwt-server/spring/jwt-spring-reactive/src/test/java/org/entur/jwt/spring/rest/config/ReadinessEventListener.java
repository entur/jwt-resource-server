package org.entur.jwt.spring.rest.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.availability.AvailabilityChangeEvent;
import org.springframework.boot.availability.ReadinessState;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

@Component
public class ReadinessEventListener {
    
    private static Logger log = LoggerFactory.getLogger(ReadinessEventListener.class);

    @EventListener
    public void onEvent(AvailabilityChangeEvent<ReadinessState> event) {
    	// note: will always refusing traffic upon shutdown
        log.info("Readiness is " + event.getState());
    }
}