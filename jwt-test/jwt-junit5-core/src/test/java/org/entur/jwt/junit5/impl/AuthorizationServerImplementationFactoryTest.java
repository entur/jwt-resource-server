package org.entur.jwt.junit5.impl;

import org.entur.jwt.junit5.AuthorizationServer;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.lang.annotation.Annotation;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

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

    @AuthorizationServer("outer")
    static class OuterTest {

        static class StaticNestedTest {
        }

        @AuthorizationServer("inner")
        static class StaticNestedWithAuthorizationServerTest {
        }

        @Nested
        class NestedTest {

            @Nested
            class NestedNestedTest {
            }
        }
    }

    @AuthorizationServer("outer")
    @MyAuthorizationServer
    static class OverriddenOuterTest {

        @Nested
        @MyAuthorizationServer(namespace = "https://other/")
        class OverridingNestedTest {
        }
    }

    @AuthorizationServer
    static class UnnamedOuterTest {

        @Nested
        @AuthorizationServer
        class UnnamedNestedTest {
        }
    }

    @MyAuthorizationServer
    @MyComposedAnnotation
    static class DuplicateIdTest {
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

    @Test
    public void testNestedClassesInheritEnclosingAuthorizationServers() {
        assertThat(getIds(factory.create(OuterTest.NestedTest.class))).containsExactly("outer");
        assertThat(getIds(factory.create(OuterTest.NestedTest.NestedNestedTest.class))).containsExactly("outer");
    }

    @Test
    public void testStaticNestedClassesDoNotInheritEnclosingAuthorizationServers() {
        // like JUnit and Spring
        assertThat(factory.create(OuterTest.StaticNestedTest.class)).isEmpty();
        assertThat(getIds(factory.create(OuterTest.StaticNestedWithAuthorizationServerTest.class))).containsExactly("inner");
    }

    @Test
    public void testNestedClassOverridesAuthorizationServerWithSameId() throws IOException {
        List<AuthorizationServerImplementation> servers = factory.create(OverriddenOuterTest.OverridingNestedTest.class);
        assertThat(getIds(servers)).containsExactly("myServer", "outer").inOrder();

        AuthorizationServerImplementation server = servers.get(0);
        assertThat(((MyAuthorizationServer) server.getAnnotation()).namespace()).isEqualTo("https://other/");

        // the keys of the overriding authorization server are published
        Map<String, Object> properties = AuthorizationServerImplementationFactory.getProperties("entur.jwt.tenants", servers);
        Path path = Paths.get(URI.create((String) properties.get("entur.jwt.tenants.myServer.jwk.location")));
        assertThat(Files.readString(path)).isEqualTo(server.getJsonWebKeys());
    }

    @Test
    public void testNestedClassRepeatsAuthorizationServer() throws IOException {
        List<AuthorizationServerImplementation> servers = factory.create(UnnamedOuterTest.UnnamedNestedTest.class);
        assertThat(servers).hasSize(1);

        // i.e. not a multi-tenant test
        assertThat(AuthorizationServerImplementationFactory.getProperties("entur.jwt.tenants", servers)).containsKey("entur.jwt.tenants.mock.jwk.location");
    }

    @Test
    public void testDuplicateIdOnSameClassFails() {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> factory.create(DuplicateIdTest.class));

        assertThat(e).hasMessageThat().contains("'myServer'");
    }
}
