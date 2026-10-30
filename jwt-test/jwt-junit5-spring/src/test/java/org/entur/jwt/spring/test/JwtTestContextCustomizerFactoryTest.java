package org.entur.jwt.spring.test;

import org.entur.jwt.junit5.AuthorizationServer;
import org.junit.jupiter.api.Test;
import org.springframework.test.context.ContextCustomizer;

import java.util.Collections;

import static com.google.common.truth.Truth.assertThat;

public class JwtTestContextCustomizerFactoryTest {

    @AuthorizationServer
    static class FirstTest {
    }

    @AuthorizationServer
    static class SecondTest {
    }

    @AuthorizationServer("other")
    static class OtherTest {
    }

    static class NoAuthorizationServerTest {
    }

    private final JwtTestContextCustomizerFactory factory = new JwtTestContextCustomizerFactory();

    private ContextCustomizer create(Class<?> testClass) {
        return factory.createContextCustomizer(testClass, Collections.emptyList());
    }

    @Test
    public void testCustomizersForSameAuthorizationServersAreEqual() {
        // so that the Spring test context cache reuses application contexts across test classes
        ContextCustomizer first = create(FirstTest.class);
        ContextCustomizer second = create(SecondTest.class);

        assertThat(first).isEqualTo(second);
        assertThat(first.hashCode()).isEqualTo(second.hashCode());
    }

    @Test
    public void testCustomizersForDifferentAuthorizationServersAreNotEqual() {
        assertThat(create(FirstTest.class)).isNotEqualTo(create(OtherTest.class));
    }

    @Test
    public void testNoCustomizerWithoutAuthorizationServer() {
        // so that configured tenants are not disabled
        assertThat(create(NoAuthorizationServerTest.class)).isNull();
    }
}
