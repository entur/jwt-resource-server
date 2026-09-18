package org.entur.jwt.spring.actuate;

import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.events.Event;
import com.nimbusds.jose.util.events.EventListener;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class ListEventListenerTest {

    private static class RecordingEventListener implements EventListener {
        final List<Event> received = new ArrayList<>();

        @Override
        public void notify(Event event) {
            received.add(event);
        }
    }

    private static Event<Object, SecurityContext> testEvent() {
        return new Event<>() {
            @Override
            public Object getSource() {
                return "source";
            }

            @Override
            public SecurityContext getContext() {
                return null;
            }
        };
    }

    @Test
    void delegatesEventToAllRegisteredListeners() {
        ListEventListener listEventListener = new ListEventListener();

        RecordingEventListener first = new RecordingEventListener();
        RecordingEventListener second = new RecordingEventListener();

        listEventListener.addEventListener(first);
        listEventListener.addEventListener(second);

        listEventListener.notify(testEvent());

        assertEquals(1, first.received.size());
        assertEquals(1, second.received.size());
    }

    @Test
    void doesNothingWhenNoListenersRegistered() {
        ListEventListener listEventListener = new ListEventListener();

        // should not throw
        listEventListener.notify(testEvent());
    }
}

