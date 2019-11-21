module org.entur.jwt.verifier.auth0 {
	exports org.entur.jwt.verifier.auth0;

	requires java.jwt;
	requires jwk.core;
	requires jwks.rsa;
	requires org.entur.jwt.jwk.auth0;
	requires org.entur.jwt.verifier;
	requires org.slf4j;
}