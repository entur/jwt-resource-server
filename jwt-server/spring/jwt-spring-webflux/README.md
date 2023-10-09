# jwt-spring-webflux

This module is not completely reactive yet, as it's using a JWK source, which is not reactive and must wrap each call in
callable.

Certificates are therefore fetched synchronously. We recommend a config that works around this (eager refresh).
