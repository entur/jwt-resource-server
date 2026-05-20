package org.entur.jwt.spring.actuate;

import com.nimbusds.jose.util.events.Event;
import com.nimbusds.jose.util.events.EventListener;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 *
 * A simple event listener that maintains a list of event listeners and
 * delegates incoming events to each registered listener.
 *
 */

public class ListEventListener implements EventListener {

    private List<EventListener> eventListeners = new CopyOnWriteArrayList<>();

    public void addEventListener(EventListener eventListener) {
        eventListeners.add(eventListener);
    }

    @Override
    public void notify(Event event) {
        for (EventListener eventListener : eventListeners) {
            eventListener.notify(event);
        }
    }
}
