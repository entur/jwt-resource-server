package org.entur.jwt.spring.actuate;

import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.events.Event;
import org.junit.jupiter.api.Test;

/**
 * These tests mainly verify that no exception is thrown, since the listener only logs.
 */
class JwkSetSourceEventListenerTest {

    private static Event<Object, SecurityContext> genericEvent() {
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
    void handlesGenericEventsWithoutThrowing() {
        JwkSetSourceEventListener listener = new JwkSetSourceEventListener("my-tenant");
        listener.notify(genericEvent());
    }
}
