module org.entur.jwt.junit5 {
	exports org.entur.jwt.junit5;
	exports org.entur.jwt.junit5.claim;
	exports org.entur.jwt.junit5.impl;

	requires org.junit.jupiter.api;
	requires org.junit.platform.commons;
	requires jjwt;
}