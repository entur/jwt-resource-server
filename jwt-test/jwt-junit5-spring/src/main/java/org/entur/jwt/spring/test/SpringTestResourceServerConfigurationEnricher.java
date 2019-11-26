package org.entur.jwt.spring.test;

import java.io.IOException;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.entur.jwt.junit5.configuration.enrich.PropertiesFileResourceServerConfigurationEnricher;
import org.entur.jwt.junit5.extention.AuthorizationServerExtension;
import org.entur.jwt.junit5.extention.AuthorizationServerTestContext;
import org.entur.jwt.junit5.extention.AuthorizationServerTestManager;
import org.entur.jwt.junit5.impl.AuthorizationServerImplementation;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.api.extension.ExtensionContext.Namespace;
import org.junit.jupiter.api.extension.ExtensionContext.Store;
import org.springframework.test.annotation.DirtiesContext.HierarchyMode;
import org.springframework.test.context.TestContext;
import org.springframework.test.context.TestContextManager;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.context.support.DependencyInjectionTestExecutionListener;
import org.springframework.util.Assert;

// https://docs.spring.io/spring/docs/current/spring-framework-reference/testing.html#testcontext-ctx-management

public class SpringTestResourceServerConfigurationEnricher extends PropertiesFileResourceServerConfigurationEnricher {

	private static final Log logger = LogFactory.getLog(SpringTestResourceServerConfigurationEnricher.class);

	/**
	 * {@link Namespace} in which {@code TestContextManagers} are stored,
	 * keyed by test class.
	 */
	private static final Namespace SPRING_EXTENTION_NAMESPACE = Namespace.create(SpringExtension.class);

	public SpringTestResourceServerConfigurationEnricher() throws IOException {
		super();
	}

	@Override
	public void beforeAll(List<AuthorizationServerImplementation> authorizationServers, ExtensionContext context) throws IOException {
		AuthorizationServerTestManager jwtTestContextManager = getJwtTestContextManager(context);

		// try to reuse the spring context
		// check if all our authorization servers were already loaded into the context

		// TODO use testContext.hasApplicationContext() for cleaner approach
		boolean dirty = checkDirty(authorizationServers, context);
		if(dirty) {
			if(logger.isDebugEnabled()) logger.debug("Authorization servers have changed, refresh spring context");

			// save context
			jwtTestContextManager.setTestContext(new AuthorizationServerTestContext(authorizationServers));

			// write new properties file
			super.beforeAll(authorizationServers, context);

			// get the spring context, approach copied from SpringExtention
			TestContextManager testContextManager = getSpringTestContextManager(context);
			TestContext testContext = testContextManager.getTestContext(); // note: loads test context, but not main context

			// see DirtiesContextBeforeModesTestExecutionListener and DirtiesContextTestExecutionListener
			testContext.markApplicationContextDirty(HierarchyMode.EXHAUSTIVE);
			testContext.setAttribute(DependencyInjectionTestExecutionListener.REINJECT_DEPENDENCIES_ATTRIBUTE, Boolean.TRUE);
		} else {
			// reconfigure mock authorization servers according to what was loaded into the context
			// this way, the (expensive) spring context can be kept
			if(logger.isDebugEnabled()) logger.debug("Authorization servers have not changed, copy keys from previuos context");
			AuthorizationServerTestContext jwtTestContext = jwtTestContextManager.getTestContext();

			// write properties, the context might be dirty even if we think its not
			super.beforeAll(jwtTestContext.toList(), context);

			// set previous encoder on the current mocks
			// so that they generate tokens signed with previous (the right) certificates
			for (AuthorizationServerImplementation authorizationServerImplementation : authorizationServers) {
				authorizationServerImplementation.setEncoder(jwtTestContext.getEncoder(authorizationServerImplementation));
			}
		}
	}

	protected boolean checkDirty(List<AuthorizationServerImplementation> authorizationServers, ExtensionContext context) {
		AuthorizationServerTestManager jwtTestContextManager = getJwtTestContextManager(context);

		AuthorizationServerTestContext testContext = jwtTestContextManager.getTestContext();

		return testContext == null || testContext.isDirty(authorizationServers);
	}

	/**
	 * Get the {@link TestContextManager} associated with the supplied {@code ExtensionContext}.
	 * @return the {@code TestContextManager} (never {@code null})
	 */
	private static TestContextManager getSpringTestContextManager(ExtensionContext context) {
		Assert.notNull(context, "ExtensionContext must not be null");
		Class<?> testClass = context.getRequiredTestClass();
		Store store = getSpringStore(context);
		return store.getOrComputeIfAbsent(testClass, TestContextManager::new, TestContextManager.class);
	}

	protected static Store getSpringStore(ExtensionContext context) {
		return context.getRoot().getStore(SPRING_EXTENTION_NAMESPACE);
	}

	/**
	 * Get the {@link TestContextManager} associated with the supplied {@code ExtensionContext}.
	 * @return the {@code TestContextManager} (never {@code null})
	 */
	private static AuthorizationServerTestManager getJwtTestContextManager(ExtensionContext context) {
		Store store = AuthorizationServerExtension.getStore(context);
		return store.getOrComputeIfAbsent(AuthorizationServerTestManager.class);
	}
}
