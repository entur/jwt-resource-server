package org.entur.jwt.junit5.extention;

import java.io.BufferedWriter;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;

import org.entur.jwt.junit5.AccessToken;
import org.entur.jwt.junit5.AuthorizationServer;
import org.entur.jwt.junit5.configuration.enrich.ResourceServerConfigurationEnricher;
import org.entur.jwt.junit5.configuration.enrich.ResourceServerConfigurationEnricherServiceLoader;
import org.entur.jwt.junit5.configuration.resolve.ResourceServerConfiguration;
import org.entur.jwt.junit5.configuration.resolve.ResourceServerConfigurationResolver;
import org.entur.jwt.junit5.configuration.resolve.ResourceServerConfigurationResolverServiceLoader;
import org.entur.jwt.junit5.impl.AccessTokenImplementationFactory;
import org.entur.jwt.junit5.impl.AuthorizationServerImplementation;
import org.entur.jwt.junit5.impl.AuthorizationServerImplementationFactory;
import org.junit.jupiter.api.extension.AfterAllCallback;
import org.junit.jupiter.api.extension.BeforeAllCallback;
import org.junit.jupiter.api.extension.BeforeEachCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.api.extension.ExtensionContext.Namespace;
import org.junit.jupiter.api.extension.ExtensionContext.Store;
import org.junit.jupiter.api.extension.ParameterContext;
import org.junit.jupiter.api.extension.ParameterResolver;

public class AuthorizationServerExtension implements ParameterResolver, BeforeAllCallback, AfterAllCallback, BeforeEachCallback, ResourceServerConfiguration {

    public static final Namespace NAMESPACE = Namespace.create(AuthorizationServerExtension.class);

    // in-memory cache for jwks
    protected static final AuthorizationServerImplementationFactory FACTORY = new AuthorizationServerImplementationFactory();

    public static AuthorizationServerImplementationFactory getFactory() {
        return FACTORY;
    }

    protected List<AuthorizationServerImplementation> servers = new ArrayList<>();
    protected List<ResourceServerConfigurationEnricher> enrichers = new ArrayList<>();
    protected List<ResourceServerConfigurationResolver> resolvers = new ArrayList<>();

    protected List<ResourceServerConfiguration> configurations = new ArrayList<>();

    public static Store getStore(ExtensionContext context) {
        return context.getRoot().getStore(NAMESPACE);
    }

    @Override
    public void beforeAll(ExtensionContext context) throws Exception {
        Class<?> testClass = context.getRequiredTestClass();

        servers = FACTORY.create(testClass);

        enrichers = ResourceServerConfigurationEnricherServiceLoader.load();
        if (enrichers.isEmpty()) {
            throw new IllegalArgumentException("No configuration enrichers registred");
        }

        // configure
        for (ResourceServerConfigurationEnricher enricher : enrichers) {
            enricher.beforeAll(servers, context);
        }

        // might be empty
        resolvers = ResourceServerConfigurationResolverServiceLoader.load();
    }

    @Override
    public void beforeEach(ExtensionContext context) throws Exception {
        List<ResourceServerConfiguration> values = new ArrayList<>();
        for (ResourceServerConfigurationResolver resolver : resolvers) {
            values.add(resolver.resolve(context));
        }
        this.configurations = values;

        for (ResourceServerConfigurationEnricher enricher : enrichers) {
            enricher.beforeEach(this, context);
        }

    }

    @Override
    public void afterAll(ExtensionContext context) throws Exception {
        servers.clear();

        for (ResourceServerConfigurationEnricher enricher : enrichers) {
            enricher.afterAll(context);
        }
        enrichers.clear();

        resolvers.clear();
    }

    @Override
    public Object resolveParameter(ParameterContext parameterContext, ExtensionContext extensionContext) {
        Optional<AccessToken> accessTokenTokenAnnotation = parameterContext.findAnnotation(AccessToken.class);
        if (accessTokenTokenAnnotation.isPresent()) {
            AccessToken accessToken = accessTokenTokenAnnotation.get();

            AuthorizationServerImplementation authorizationServerImplementation;
            String authorizationServer = accessToken.by();
            if (authorizationServer != null && !authorizationServer.isEmpty()) {
                authorizationServerImplementation = getAuthorizationServerImplementation(authorizationServer);
                if(authorizationServerImplementation == null) {
                    throw new IllegalArgumentException("Unknown authorization server " + authorizationServer);
                }
            } else if (servers.size() == 1) {
                authorizationServerImplementation = servers.iterator().next();
            } else {
                throw new IllegalArgumentException("Please specify AccessToken authorization-server attribute when using multiple authorization servers");
            }

            AccessTokenImplementationFactory factory = new AccessTokenImplementationFactory(authorizationServerImplementation);

            String token = factory.create(accessToken, parameterContext, extensionContext, this);
            
            return "Bearer " + token;
        }
        throw new IllegalArgumentException("Unable to resolve parameter");
    }

    @Override
    public boolean supportsParameter(ParameterContext parameterContext, ExtensionContext extensionContext) {
        Optional<AccessToken> accessTokenTokenAnnotation = parameterContext.findAnnotation(AccessToken.class);
        if (accessTokenTokenAnnotation.isPresent()) {
            AccessToken accessToken = accessTokenTokenAnnotation.get();

            if (servers.size() == 1) {
                return true;
            }

            String authorizationServer = accessToken.by();
            if (authorizationServer == null || authorizationServer.isEmpty()) {
                throw new IllegalArgumentException("Please specify AccessToken authorization-server 'by' attribute when using multiple authorization servers");
            }
            if (!authorizationServer.isEmpty()) {
                if (getAuthorizationServerImplementation(authorizationServer) == null) {
                    throw new IllegalArgumentException("Unknown authorization server " + authorizationServer);
                }
                return true;
            }

            throw new IllegalArgumentException("Unknown authorization-server attribute '" + authorizationServer + "' for access-token " + accessTokenTokenAnnotation);
        }
        return false;
    }

    protected AuthorizationServerImplementation getAuthorizationServerImplementation(String id) {
        for (AuthorizationServerImplementation issuer : servers) {
            if (issuer.getAuthorizationServer().value().equals(id)) {
                return issuer;
            }
        }
        return null;
    }

    @Override
    public String getProperty(String id, String propertyName) {
        if (configurations.isEmpty()) {
            if (propertyName.equals("issuer")) {
                return toDefaultIssuer(id);
            }
        } else {
            for (ResourceServerConfiguration r : configurations) {
                String value = r.getProperty(id, propertyName);
                if (value != null) {
                    return value;
                }
            }
        }
        throw new IllegalArgumentException("Unknown property " + propertyName + " for tenant " + id);
    }

    public static String toIssuer(AccessToken token) {
        return toDefaultIssuer(token.by());
    }

    public static String toIssuer(AuthorizationServer server) {
        return toDefaultIssuer(server.value());
    }

    public static String toDefaultIssuer(String tenant) {
        if (tenant.isEmpty()) {
            return "https://mock.issuer.xyz";
        }
        return "https://mock.issuer." + tenant.substring(tenant.lastIndexOf('.') + 1) + ".xyz";
    }

    public static Path detectParentPath() {
        Path mavenPath =  Paths.get("target");
        if (Files.exists(mavenPath)) {
            return Paths.get("target","jwt.junit5.properties");
        }
        Path gradlePath =  Paths.get("build");
        if (Files.exists(gradlePath)) {
            return Paths.get("build","jwt.junit5.properties");
        }
        return Paths.get("jwt.junit5.properties");
    }

    public static Path detectPath() {
        Path mavenPath =  Paths.get("target","jwt.junit5.properties");
        if (Files.exists(mavenPath)) {
            return mavenPath;
        }
        Path gradlePath =  Paths.get("build","jwt.junit5.properties");
        if (Files.exists(gradlePath)) {
            return gradlePath;
        }
        return Paths.get("jwt.junit5.properties");
    }


}
