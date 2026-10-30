package org.entur.jwt.junit5.extention;

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
import org.junit.jupiter.api.extension.ParameterResolutionException;
import org.junit.jupiter.api.extension.ParameterResolver;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

public class AuthorizationServerExtension implements ParameterResolver, BeforeAllCallback, AfterAllCallback, BeforeEachCallback, ResourceServerConfiguration {

    public static final Namespace NAMESPACE = Namespace.create(AuthorizationServerExtension.class);

    protected static final String KEY_CONFIGURATIONS = "configurations";

    // in-memory cache for jwks
    protected static final AuthorizationServerImplementationFactory FACTORY = new AuthorizationServerImplementationFactory();

    public static AuthorizationServerImplementationFactory getFactory() {
        return FACTORY;
    }

    protected List<AuthorizationServerImplementation> servers = new ArrayList<>();
    protected List<ResourceServerConfigurationEnricher> enrichers = new ArrayList<>();
    // might be empty
    protected List<ResourceServerConfigurationResolver> resolvers = ResourceServerConfigurationResolverServiceLoader.load();

    protected List<ResourceServerConfiguration> configurations = new ArrayList<>();

    public static Store getStore(ExtensionContext context) {
        return context.getRoot().getStore(NAMESPACE);
    }

    @Override
    public void beforeAll(ExtensionContext context) throws Exception {
        initialize(context);
    }

    /**
     * Initialize the authorization servers for the test class, once. With a per-class test instance lifecycle,
     * constructor parameters are resolved before beforeAll.
     *
     * @param context extension context
     * @throws Exception if the configuration could not be enriched
     */

    protected void initialize(ExtensionContext context) throws Exception {
        Class<?> testClass = context.getRequiredTestClass();
        Store store = context.getStore(NAMESPACE);
        if (store.get(testClass) != null) {
            // already initialized
            return;
        }

        servers = getServers(context);
        store.put(testClass, servers);

        enrichers = ResourceServerConfigurationEnricherServiceLoader.load();
        if (enrichers.isEmpty()) {
            throw new IllegalArgumentException("No configuration enrichers registred");
        }

        // configure
        for (ResourceServerConfigurationEnricher enricher : enrichers) {
            enricher.beforeAll(servers, context);
        }
    }

    @Override
    public void beforeEach(ExtensionContext context) throws Exception {
        List<ResourceServerConfiguration> values = resolveConfigurations(context);
        this.configurations = values;

        // for resolving the parameters of this test
        context.getStore(NAMESPACE).put(KEY_CONFIGURATIONS, values);

        for (ResourceServerConfigurationEnricher enricher : enrichers) {
            enricher.beforeEach(this, context);
        }

    }

    protected List<ResourceServerConfiguration> resolveConfigurations(ExtensionContext context) throws Exception {
        List<ResourceServerConfiguration> values = new ArrayList<>();
        for (ResourceServerConfigurationResolver resolver : resolvers) {
            ResourceServerConfiguration configuration = resolver.resolve(context);
            if (configuration != null) { // i.e. resolver is not applicable for this test
                values.add(configuration);
            }
        }
        return values;
    }

    @Override
    public void afterAll(ExtensionContext context) throws Exception {
        servers.clear();

        for (ResourceServerConfigurationEnricher enricher : enrichers) {
            enricher.afterAll(context);
        }
        enrichers.clear();
    }

    @Override
    public Object resolveParameter(ParameterContext parameterContext, ExtensionContext extensionContext) {
        Optional<AccessToken> accessTokenTokenAnnotation = parameterContext.findAnnotation(AccessToken.class);
        if (accessTokenTokenAnnotation.isPresent()) {
            AccessToken accessToken = accessTokenTokenAnnotation.get();

            List<AuthorizationServerImplementation> implementations = getServers(extensionContext);

            AuthorizationServerImplementation authorizationServerImplementation;
            String authorizationServer = accessToken.by();
            if (authorizationServer != null && !authorizationServer.isEmpty()) {
                authorizationServerImplementation = getAuthorizationServerImplementation(implementations, authorizationServer);
                if(authorizationServerImplementation == null) {
                    throw new IllegalArgumentException("Unknown authorization server " + authorizationServer);
                }
            } else if (implementations.size() == 1) {
                authorizationServerImplementation = implementations.iterator().next();
            } else {
                throw new IllegalArgumentException("Please specify AccessToken authorization-server attribute when using multiple authorization servers");
            }

            AccessTokenImplementationFactory factory = new AccessTokenImplementationFactory(authorizationServerImplementation);

            String token = factory.create(accessToken, parameterContext, extensionContext, getConfiguration(extensionContext));
            
            return "Bearer " + token;
        }
        throw new IllegalArgumentException("Unable to resolve parameter");
    }

    @Override
    public boolean supportsParameter(ParameterContext parameterContext, ExtensionContext extensionContext) {
        Optional<AccessToken> accessTokenTokenAnnotation = parameterContext.findAnnotation(AccessToken.class);
        if (accessTokenTokenAnnotation.isPresent()) {
            AccessToken accessToken = accessTokenTokenAnnotation.get();

            List<AuthorizationServerImplementation> implementations = getServers(extensionContext);
            if (implementations.size() == 1) {
                return true;
            }

            String authorizationServer = accessToken.by();
            if (authorizationServer == null || authorizationServer.isEmpty()) {
                throw new IllegalArgumentException("Please specify AccessToken authorization-server 'by' attribute when using multiple authorization servers");
            }
            if (!authorizationServer.isEmpty()) {
                if (getAuthorizationServerImplementation(implementations, authorizationServer) == null) {
                    throw new IllegalArgumentException("Unknown authorization server " + authorizationServer);
                }
                return true;
            }

            throw new IllegalArgumentException("Unknown authorization-server attribute '" + authorizationServer + "' for access-token " + accessTokenTokenAnnotation);
        }
        return false;
    }

    /**
     * Get the authorization servers of the test class. Parameters might be resolved before beforeAll,
     * i.e. constructor parameters with a per-class test instance lifecycle.
     *
     * @param context extension context
     * @return authorization servers
     */

    protected List<AuthorizationServerImplementation> getServers(ExtensionContext context) {
        // note: the factory returns the same implementations for the same authorization servers
        return FACTORY.create(context.getRequiredTestClass());
    }

    protected AuthorizationServerImplementation getAuthorizationServerImplementation(String id) {
        return getAuthorizationServerImplementation(servers, id);
    }

    protected static AuthorizationServerImplementation getAuthorizationServerImplementation(List<AuthorizationServerImplementation> implementations, String id) {
        for (AuthorizationServerImplementation issuer : implementations) {
            if (issuer.getAuthorizationServer().value().equals(id)) {
                return issuer;
            }
        }
        return null;
    }

    /**
     * Get the configuration for resolving a parameter. The configuration is resolved in beforeEach, but parameters
     * might also be resolved before that, i.e. for constructors and {@literal @}BeforeAll methods.
     *
     * @param context extension context
     * @return configuration
     */

    protected ResourceServerConfiguration getConfiguration(ExtensionContext context) {
        @SuppressWarnings("unchecked")
        List<ResourceServerConfiguration> values = context.getStore(NAMESPACE).get(KEY_CONFIGURATIONS, List.class);
        if (values == null) {
            try {
                initialize(context);

                values = resolveConfigurations(context);
            } catch (Exception e) {
                throw new ParameterResolutionException("Unable to resolve resource server configuration", e);
            }
        }
        List<ResourceServerConfiguration> resolved = values;
        return (id, propertyName) -> getProperty(resolved, id, propertyName);
    }

    @Override
    public String getProperty(String id, String propertyName) {
        return getProperty(configurations, id, propertyName);
    }

    protected static String getProperty(List<ResourceServerConfiguration> configurations, String id, String propertyName) {
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
