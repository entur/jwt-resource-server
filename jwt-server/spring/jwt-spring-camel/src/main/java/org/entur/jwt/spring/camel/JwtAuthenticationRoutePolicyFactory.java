package org.entur.jwt.spring.camel;

import org.apache.camel.CamelContext;
import org.apache.camel.model.RouteDefinition;
import org.apache.camel.spi.RoutePolicy;
import org.apache.camel.spi.RoutePolicyFactory;

/**
 * Factory for a policy which sets the authentication header on exchange messages. 
 * 
 */

public class JwtAuthenticationRoutePolicyFactory implements RoutePolicyFactory {

	private final JwtAuthenticationRoutePolicy jwtRoutePolicy;

	public JwtAuthenticationRoutePolicyFactory(JwtAuthenticationProcessor processor) {
		this.jwtRoutePolicy = new JwtAuthenticationRoutePolicy(processor);
	}

	@Override
	public RoutePolicy createRoutePolicy(CamelContext camelContext, String routeId, RouteDefinition route) {
		return jwtRoutePolicy;
	}

}
