package org.entur.jwt.spring.test;

import org.entur.jwt.junit5.configuration.enrich.PropertiesFileResourceLocksProvider;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.Extension;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class SpringTestResourceServerConfigurationResolverTest {

    static class MySpringExtension extends SpringExtension {
    }

    @ExtendWith(SpringExtension.class)
    static class ExtendWithSpringExtension {
    }

    @ExtendWith(MySpringExtension.class)
    static class ExtendWithSpringExtensionSubclass {
    }

    static class RegisterSpringExtension {
        @RegisterExtension
        static SpringExtension spring = new SpringExtension();
    }

    static class RegisterSpringExtensionAsExtension {
        @RegisterExtension
        static Extension spring = new SpringExtension();
    }

    static class NotSpring {
    }

    @Test
    public void testDetectsSpringExtension() {
        assertTrue(SpringTestResourceServerConfigurationResolver.isSpringTest(ExtendWithSpringExtension.class));
        assertTrue(SpringTestResourceServerConfigurationResolver.isSpringTest(ExtendWithSpringExtensionSubclass.class));
        assertTrue(SpringTestResourceServerConfigurationResolver.isSpringTest(RegisterSpringExtension.class));
        assertTrue(SpringTestResourceServerConfigurationResolver.isSpringTest(RegisterSpringExtensionAsExtension.class));

        assertFalse(SpringTestResourceServerConfigurationResolver.isSpringTest(NotSpring.class));
    }

    @Test
    public void testSpringTestsRunInParallel() {
        // the properties file enricher is not used for Spring tests, so they are not locked
        assertTrue(new PropertiesFileResourceLocksProvider().provideForClass(ExtendWithSpringExtension.class).isEmpty());
    }
}
