package org.entur.jwt.spring.test;

import org.entur.jwt.junit5.configuration.resolve.ResourceServerConfiguration;
import org.entur.jwt.junit5.configuration.resolve.ResourceServerConfigurationResolver;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.api.extension.ExtensionContext.Namespace;
import org.junit.jupiter.api.extension.ExtensionContext.Store;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.platform.commons.support.HierarchyTraversalMode;
import org.junit.platform.commons.support.ReflectionSupport;
import org.springframework.context.ApplicationContext;
import org.springframework.core.annotation.MergedAnnotations;
import org.springframework.core.annotation.MergedAnnotations.SearchStrategy;
import org.springframework.core.env.Environment;
import org.springframework.test.context.TestContextManager;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.util.Assert;
import org.springframework.util.ClassUtils;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.Arrays;
import java.util.List;

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

    /**
     * @param testClass test class
     * @return true if the SpringExtension (or a subclass) is registered for the test class, or for an enclosing class
     * of a {@literal @}Nested test class, using {@literal @}ExtendWith or a static {@literal @}RegisterExtension field
     */

    protected static boolean isSpringTest(Class<?> testClass) {
        boolean extendWith = MergedAnnotations.search(SearchStrategy.TYPE_HIERARCHY)
                .withEnclosingClasses(ClassUtils::isInnerClass)
                .from(testClass)
                .stream(ExtendWith.class)
                .anyMatch(annotation -> Arrays.stream(annotation.getClassArray("value")).anyMatch(SpringExtension.class::isAssignableFrom));
        if (extendWith) {
            return true;
        }
        // note: instance fields are registered after the test instance is created, i.e. after its constructor parameters are resolved
        for (Class<?> c = testClass; c != null; c = ClassUtils.isInnerClass(c) ? c.getEnclosingClass() : null) {
            List<Field> fields = ReflectionSupport.findFields(c, field -> Modifier.isStatic(field.getModifiers()) && field.isAnnotationPresent(RegisterExtension.class), HierarchyTraversalMode.TOP_DOWN);
            for (Field field : fields) {
                if (SpringExtension.class.isAssignableFrom(field.getType()) || ReflectionSupport.tryToReadFieldValue(field, null).toOptional().orElse(null) instanceof SpringExtension) {
                    return true;
                }
            }
        }
        return false;
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
