# jwt-spring-web
This module is intended to work with concrete framework implementations like [jwt-spring-auth0-webflux].

This module is not completely reactive yet, as it's using [jwt-verifier-core], which is not reactive.
Certificates are therefore fetched synchronously. We recommend a config that works around this (eager refresh).  

[jwt-spring-auth0-webflux]:              ../jwt-spring-auth0-webflux
[jwt-verifier-core]:                     ../../jwt-verifier/jwt-verifier-core
