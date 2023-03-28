# jwt-spring-web

This module is intended to work with concrete framework implementations like [jwt-spring-auth0-webflux].

This module is not completely reactive yet, as it's using a JWK source, which is not reactive and must wrap each call in
callable.

Certificates are therefore fetched synchronously. We recommend a config that works around this (eager refresh).

[jwt-spring-auth0-webflux]:              ../jwt-spring-auth0-webflux
