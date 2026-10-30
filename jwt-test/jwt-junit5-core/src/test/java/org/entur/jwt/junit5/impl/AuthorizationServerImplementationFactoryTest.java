package org.entur.jwt.junit5.impl;

import org.entur.jwt.junit5.AuthorizationServer;
import org.junit.jupiter.api.Test;

import java.lang.annotation.Annotation;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.util.ArrayList;
import java.util.List;

import static com.google.common.truth.Truth.assertThat;

public class AuthorizationServerImplementationFactoryTest {

    @Retention(RetentionPolicy.RUNTIME)
    @Target(ElementType.TYPE)
    @MyAuthorizationServer(namespace = "https://my.namespace/")
    @interface MyComposedAnnotation {
    }

    @Retention(RetentionPolicy.RUNTIME)
    @Target(ElementType.TYPE)
    @AuthorizationServer("first")
    @AuthorizationServer("second")
    @interface MyAuthorizationServers {
    }

    @Retention(RetentionPolicy.RUNTIME)
    @Target(ElementType.TYPE)
    @MyAuthorizationServers
    @interface MyComposedListAnnotation {
    }

    @MyAuthorizationServer(namespace = "https://my.namespace/")
    static class DirectTest {
    }

    @MyComposedAnnotation
    static class ComposedTest {
    }

    @MyComposedListAnnotation
    static class ComposedListTest {
    }

    private final AuthorizationServerImplementationFactory factory = new AuthorizationServerImplementationFactory();

    private static List<String> getIds(List<AuthorizationServerImplementation> servers) {
        List<String> ids = new ArrayList<>();
        for (AuthorizationServerImplementation server : servers) {
            ids.add(server.getId());
        }
        return ids;
    }

    @Test
    public void testComposedAnnotationSourceIsMetaAnnotatedAnnotation() {
        // so that the encoder sees the attributes of the annotation which carries the @AuthorizationServer
        List<AuthorizationServerImplementation> servers = factory.create(ComposedTest.class);
        assertThat(getIds(servers)).containsExactly("myServer");

        Annotation annotation = servers.get(0).getAnnotation();
        assertThat(annotation).isInstanceOf(MyAuthorizationServer.class);
        assertThat(((MyAuthorizationServer) annotation).namespace()).isEqualTo("https://my.namespace/");
    }

    @Test
    public void testComposedAnnotationReusesDirectAnnotationImplementation() {
        // same source annotation, so same keys
        assertThat(factory.create(ComposedTest.class)).isEqualTo(factory.create(DirectTest.class));
    }

    @Test
    public void testComposedListAnnotationSourceIsMetaAnnotatedAnnotation() {
        List<AuthorizationServerImplementation> servers = factory.create(ComposedListTest.class);
        assertThat(getIds(servers)).containsExactly("first", "second").inOrder();

        for (AuthorizationServerImplementation server : servers) {
            assertThat(server.getAnnotation()).isInstanceOf(MyAuthorizationServers.class);
        }
    }
}
