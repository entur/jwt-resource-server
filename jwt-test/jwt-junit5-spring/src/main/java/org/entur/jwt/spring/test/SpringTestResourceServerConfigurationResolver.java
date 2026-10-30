package org.entur.jwt.spring.test;

import org.entur.jwt.junit5.configuration.resolve.ResourceServerConfiguration;
import org.entur.jwt.junit5.configuration.resolve.ResourceServerConfigurationResolver;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.api.extension.ExtensionContext.Namespace;
import org.junit.jupiter.api.extension.ExtensionContext.Store;
import org.springframework.context.ApplicationContext;
import org.springframework.core.annotation.MergedAnnotations;
import org.springframework.core.annotation.MergedAnnotations.SearchStrategy;
import org.springframework.core.env.Environment;
import org.springframework.test.context.TestContextManager;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.util.Assert;
import org.springframework.util.ClassUtils;

import java.util.Arrays;

/**
 * 
 * Resolves properties configured in the Spring context, useful for creating a
 * mock token.
 * 
 */

public class SpringTestResourceServerConfigurationResolver implements ResourceServerConfigurationResolver {

    /**
     * {@link Namespace} in which {@code TestContextManagers} are stored, keyed by
     * test class.
     */
    private static final Namespace NAMESPACE = Namespace.create(SpringExtension.class);

    @Override
    public ResourceServerConfiguration resolve(ExtensionContext context) throws Exception {
        if (getTestContextManager(context) == null && !isSpringTest(context.getRequiredTestClass())) {
            // not a Spring test
            return null;
        }
        // note: the test context manager might not exist yet, i.e. when resolving constructor parameters with
        // a per-class test instance lifecycle, so get the application context like the SpringExtension does
        ApplicationContext applicationContext = SpringExtension.getApplicationContext(context);

        Environment environment = applicationContext.getEnvironment();

        return new JwtEnvironmentResourceServerConfiguration(environment, "entur.jwt.tenants", ".enabled");
    }

    protected static boolean isSpringTest(Class<?> testClass) {
        // i.e. the SpringExtension is registered for the test class, or for an enclosing class of a @Nested test class
        return MergedAnnotations.search(SearchStrategy.TYPE_HIERARCHY)
                .withEnclosingClasses(ClassUtils::isInnerClass)
                .from(testClass)
                .stream(ExtendWith.class)
                .anyMatch(extendWith -> Arrays.asList(extendWith.getClassArray("value")).contains(SpringExtension.class));
    }

    public static ApplicationContext getApplicationContext(ExtensionContext context) {
        return getTestContextManager(context).getTestContext().getApplicationContext();
    }

    protected static TestContextManager getTestContextManager(ExtensionContext context) {
        Assert.notNull(context, "ExtensionContext must not be null");
        Class<?> testClass = context.getRequiredTestClass();
        Store store = getStore(context);
        return store.get(testClass, TestContextManager.class);
    }

    protected static Store getStore(ExtensionContext context) {
        return context.getRoot().getStore(NAMESPACE);
    }
}
