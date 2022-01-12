# jwt-spring-web
This module is intended to work with concrete framework implementations like [jwt-spring-auth0-webflux].

This module is not completely reactive yet, as it's using [jwt-verifier-core], which is not reactive.
//todo: ikke er fullt ut reaktiv, ettersom henting av sertifikater er synkront. Anbefal en konfig som jobber rundt dette (altså eager refresh)

[jwt-spring-auth0-webflux]:              ../jwt-spring-auth0-webflux
[jwt-verifier-core]:                     ../../jwt-verifier/jwt-verifier-core
