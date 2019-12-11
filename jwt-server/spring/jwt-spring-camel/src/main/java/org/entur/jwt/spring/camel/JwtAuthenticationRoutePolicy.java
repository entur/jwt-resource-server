package org.entur.jwt.spring.camel;

import org.apache.camel.Exchange;
import org.apache.camel.Route;
import org.apache.camel.spi.RoutePolicy;

public class JwtAuthenticationRoutePolicy implements RoutePolicy {

    private final JwtAuthenticationProcessor jwtProcessor;

    public JwtAuthenticationRoutePolicy(JwtAuthenticationProcessor jwtAuthenticationToSubjectProcessor) {
        super();
        this.jwtProcessor = jwtAuthenticationToSubjectProcessor;
    }

    @Override
    public void onInit(Route route) {
        // NOOP
    }

    @Override
    public void onRemove(Route route) {
        // NOOP

    }

    @Override
    public void onStart(Route route) {
        // NOOP

    }

    @Override
    public void onStop(Route route) {
        // NOOP

    }

    @Override
    public void onSuspend(Route route) {
        // NOOP

    }

    @Override
    public void onResume(Route route) {
        // NOOP

    }

    @Override
    public void onExchangeBegin(Route route, Exchange exchange) {
        jwtProcessor.process(exchange);
    }

    @Override
    public void onExchangeDone(Route route, Exchange exchange) {
        // NOOP

    }

}
