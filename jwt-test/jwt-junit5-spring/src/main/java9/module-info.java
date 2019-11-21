import org.entur.jwt.junit5.impl.AuthorizationServerImplementationWriter;

module org.entur.jwt.spring.test {
	exports org.entur.jwt.spring.test;

	requires org.entur.jwt.junit5;
	
	provides AuthorizationServerImplementationWriter with SystemPropertiesAuthorizationServerImplementationWriter
}