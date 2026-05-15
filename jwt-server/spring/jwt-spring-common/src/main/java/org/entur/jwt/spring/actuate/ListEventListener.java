package org.entur.jwt.spring.actuate;

import com.nimbusds.jose.util.events.Event;
import com.nimbusds.jose.util.events.EventListener;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class ListEventListener implements EventListener {

    private List<EventListener> eventListeners = Collections.emptyList();

    public void addEventListener(EventListener eventListener) {
        List<EventListener> newEventListeners = new ArrayList<>(eventListeners);
        newEventListeners.add(eventListener);
        this.eventListeners = newEventListeners;
    }

    @Override
    public void notify(Event event) {
        for (EventListener eventListener : eventListeners) {
            eventListener.notify(event);
        }
    }
}
