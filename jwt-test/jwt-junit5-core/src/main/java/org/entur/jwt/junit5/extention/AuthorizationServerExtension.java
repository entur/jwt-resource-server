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

    /**
     * The authorization servers and enrichers of a test class. Kept in the store of the test class, as an extension
     * instance is shared by a test class and its {@literal @}Nested test classes, which might run in parallel.
     */
    protected record TestClassState(List<AuthorizationServerImplementation> servers, List<ResourceServerConfigurationEnricher> enrichers) {
    }

    // of the last initialized test class; prefer the state in the store of the test class
    protected List<AuthorizationServerImplementation> servers = new ArrayList<>();
    protected List<ResourceServerConfigurationEnricher> enrichers = new ArrayList<>();
    // might be empty
    protected List<ResourceServerConfigurationResolver> resolvers = ResourceServerConfigurationResolverServiceLoader.load();

    // of the last test; prefer the configurations in the store of the test
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

    protected synchronized void initialize(ExtensionContext context) throws Exception {
        Class<?> testClass = context.getRequiredTestClass();
        Store store = context.getStore(NAMESPACE);
        if (store.get(testClass) != null) {
            // already initialized
            return;
        }

        List<AuthorizationServerImplementation> testClassServers = getServers(context);

        List<ResourceServerConfigurationEnricher> testClassEnrichers = ResourceServerConfigurationEnricherServiceLoader.load();
        if (testClassEnrichers.isEmpty()) {
            throw new IllegalArgumentException("No configuration enrichers registred");
        }

        // configure
        for (ResourceServerConfigurationEnricher enricher : testClassEnrichers) {
            enricher.beforeAll(testClassServers, context);
        }

        store.put(testClass, new TestClassState(testClassServers, testClassEnrichers));

        servers = testClassServers;
        enrichers = testClassEnrichers;
    }

    /**
     * @param context extension context of the test class (or one of its tests)
     * @return the authorization servers and enrichers of the test class, or null if not initialized
     */

    protected TestClassState getTestClassState(ExtensionContext context) {
        // note: the store also looks up the stores of the enclosing contexts, i.e. of the test class of a test
        return context.getStore(NAMESPACE).get(context.getRequiredTestClass(), TestClassState.class);
    }

    @Override
    public void beforeEach(ExtensionContext context) throws Exception {
        List<ResourceServerConfiguration> values = resolveConfigurations(context);
        this.configurations = values;

        // for resolving the parameters of this test
        context.getStore(NAMESPACE).put(KEY_CONFIGURATIONS, values);

        TestClassState state = getTestClassState(context);
        if (state != null) {
            ResourceServerConfiguration configuration = getConfiguration(context);
            for (ResourceServerConfigurationEnricher enricher : state.enrichers()) {
                enricher.beforeEach(configuration, context);
            }
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
        TestClassState state = getTestClassState(context);
        if (state != null) {
            for (ResourceServerConfigurationEnricher enricher : state.enrichers()) {
                enricher.afterAll(context);
            }
        }
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
                authorizationServerImplementation = getAuthorizationServerImplementation(extensionContext, authorizationServer);
                if(authorizationServerImplementation == null) {
                    throw new IllegalArgumentException("Unknown authorization server " + authorizationServer);
                }
            } else if (implementations.size() == 1) {
                authorizationServerImplementation = implementations.iterator().next();
            } else {
                throw new IllegalArgumentException("Please specify AccessToken authorization-server attribute when using multiple authorization servers");
            }

            AccessTokenImplementationFactory factory = new AccessTokenImplementationFactory(authorizationServerImplementation);

            // a token without authorization server id is for the authorization server resolved above
            String id = authorizationServerImplementation.getId();
            ResourceServerConfiguration configuration = getConfiguration(extensionContext);
            ResourceServerConfiguration tokenConfiguration = (tenantId, propertyName) -> configuration.getProperty(tenantId == null || tenantId.isEmpty() ? id : tenantId, propertyName);

            String token = factory.create(accessToken, parameterContext, extensionContext, tokenConfiguration);
            
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
                if (getAuthorizationServerImplementation(extensionContext, authorizationServer) == null) {
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

    /**
     * Get an authorization server of the test class.
     *
     * @param context extension context of the test (or test class)
     * @param id authorization server id
     * @return the authorization server, or null if not found
     */

    protected AuthorizationServerImplementation getAuthorizationServerImplementation(ExtensionContext context, String id) {
        return getAuthorizationServerImplementation(getServers(context), id);
    }

    /**
     * @param id authorization server id
     * @return the authorization server of the last initialized test class
     * @deprecated not safe for {@literal @}Nested test classes or test classes running in parallel,
     * use (and override) {@link #getAuthorizationServerImplementation(ExtensionContext, String)}
     */

    @Deprecated
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
     * Get the configuration for resolving a parameter (i.e. the issuer of an access-token), and for the enrichers.
     * The configuration is resolved in beforeEach, but parameters might also be resolved before that, i.e. for
     * constructors and {@literal @}BeforeAll methods. Override to customize the configuration of a test.
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

    /**
     * @deprecated returns the configuration of the last test, which is not safe for test classes running in parallel,
     * use (and override) {@link #getConfiguration(ExtensionContext)}
     */

    @Deprecated
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
