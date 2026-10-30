package org.entur.jwt.junit5.configuration.enrich;

import org.entur.jwt.junit5.configuration.resolve.ResourceServerConfiguration;
import org.entur.jwt.junit5.extention.AuthorizationServerExtension;
import org.entur.jwt.junit5.impl.AuthorizationServerImplementation;
import org.entur.jwt.junit5.impl.AuthorizationServerImplementationFactory;
import org.junit.jupiter.api.extension.ExtensionContext;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.ObjectNode;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

/**
 * Writes the authorization servers of a test class to a properties file, i.e. the issuer and JWK location of each
 * tenant (the JWKs are written to a file per tenant, next to the properties file).
 * <br><br>
 * The file is shared by the test classes. Each (top-level) test class replaces it, its {@literal @}Nested test classes
 * add their authorization servers to it. Authorization servers with the same id (i.e. of a {@literal @}Nested test class
 * which overrides an authorization server) publish the keys of both, at the same location. Test classes using this
 * enricher do not run in parallel with each other, see {@link PropertiesFileResourceLocksProvider}.
 */

public class PropertiesFileResourceServerConfigurationEnricher extends AbstractPropertiesResourceServerConfigurationEnricher {

    private static final JsonMapper JSON_MAPPER = JsonMapper.builder().build();

    private static final String JWK_LOCATION_PROPERTY = ".jwk.location";

    // guards writing the output files of this JVM
    private static final Object LOCK = new Object();

    // the top-level test class which last wrote each output file
    private static final Map<Path, Class<?>> WRITERS = new HashMap<>();

    protected Path output;

    public PropertiesFileResourceServerConfigurationEnricher() throws IOException {
        this("entur.jwt.tenants", AuthorizationServerExtension.detectParentPath());
    }

    public PropertiesFileResourceServerConfigurationEnricher(String prefix, Path output) {
        super(prefix);
        this.output = output;
    }

    public void setOutput(Path output) {
        this.output = output;
    }

    @Override
    public void beforeAll(List<AuthorizationServerImplementation> authorizationServers, ExtensionContext context) throws IOException {
        Class<?> topLevelTestClass = context != null ? AuthorizationServerImplementationFactory.getTopLevelTestClass(context.getRequiredTestClass()) : null;

        write(authorizationServers, topLevelTestClass);
    }

    /**
     * Write the authorization servers of a test class.
     *
     * @param authorizationServers the authorization servers of the test class
     * @param topLevelTestClass the top-level test class, i.e. the test class itself or the enclosing class of a {@literal @}Nested test class
     * @throws IOException if the files could not be written
     */

    protected void write(List<AuthorizationServerImplementation> authorizationServers, Class<?> topLevelTestClass) throws IOException {
        for (AuthorizationServerImplementation authorizationServer : authorizationServers) {
            if (authorizationServer.getId().isEmpty() && authorizationServers.size() > 1) {
                throw new IllegalArgumentException("Specify authorization server id in multi-tenant tests.");
            }
        }

        synchronized (LOCK) {
            Path path = output.toAbsolutePath().normalize();

            // the test classes of a top-level test class share the file, other test classes replace it
            boolean merge = topLevelTestClass != null && WRITERS.get(path) == topLevelTestClass && Files.exists(path);
            WRITERS.put(path, topLevelTestClass);

            Properties p = new Properties();
            if (merge) {
                try (InputStream in = Files.newInputStream(path)) {
                    p.load(in);
                }
            }

            for (AuthorizationServerImplementation authorizationServer : authorizationServers) {
                String tenant = authorizationServer.getId().isEmpty() ? AuthorizationServerImplementationFactory.ON_THE_FLY_TENANT : authorizationServer.getId();
                String key = prefix + "." + tenant;

                // as read by PropertiesFileAuthorizationServerConfigurationResolver
                String issuer = AuthorizationServerExtension.toIssuer(authorizationServer.getAuthorizationServer());
                String existingIssuer = p.getProperty(key + ".issuer");
                if (existingIssuer != null && !existingIssuer.equals(issuer)) {
                    throw new IllegalArgumentException("Authorization servers with different issuers " + existingIssuer + " and " + issuer + " for tenant '" + tenant + "' (an authorization server without id uses tenant '" + AuthorizationServerImplementationFactory.ON_THE_FLY_TENANT + "')");
                }
                p.put(key + ".issuer", issuer);
                if (authorizationServer.getId().isEmpty()) {
                    p.put(key + AuthorizationServerImplementationFactory.ON_THE_FLY_PROPERTY, "true");
                }

                // the same location for the tenant, so that a resource server which reloads the keys
                // also gets the keys added by a @Nested test class
                Path jwks = getJsonWebKeysPath(path, tenant);
                String content = authorizationServer.getJsonWebKeys();
                if (merge && p.getProperty(key + JWK_LOCATION_PROPERTY) != null && Files.exists(jwks)) {
                    content = mergeJsonWebKeys(Files.readString(jwks, StandardCharsets.UTF_8), content);
                }
                AuthorizationServerImplementationFactory.writeAtomically(jwks, content);
                p.put(key + JWK_LOCATION_PROPERTY, jwks.toUri().toString());
            }

            // the byte stream variant escapes non-ASCII characters, as expected by Properties.load(InputStream)
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            p.store(out, null);
            AuthorizationServerImplementationFactory.writeAtomically(path, out.toByteArray());
        }
    }

    protected Path getJsonWebKeysPath(Path path, String tenant) {
        return path.resolveSibling(path.getFileName() + "." + URLEncoder.encode(tenant, StandardCharsets.UTF_8) + ".jwk.json");
    }

    /**
     * Merge the keys of two JWK sets, i.e. of authorization servers with the same id.
     *
     * @param jwks JWK set
     * @param otherJwks other JWK set
     * @return JWK set with the keys of both
     */

    protected String mergeJsonWebKeys(String jwks, String otherJwks) {
        Set<JsonNode> keys = new LinkedHashSet<>();
        for (String content : new String[] {jwks, otherJwks}) {
            for (JsonNode key : JSON_MAPPER.readTree(content).path("keys")) {
                keys.add(key);
            }
        }
        ObjectNode merged = JSON_MAPPER.createObjectNode();
        ArrayNode array = merged.putArray("keys");
        keys.forEach(array::add);

        return JSON_MAPPER.writeValueAsString(merged);
    }

    @Override
    public void beforeEach(ResourceServerConfiguration configuration, ExtensionContext context) {
        // do nothing
    }

    @Override
    public void afterAll(ExtensionContext context) throws IOException {
        // do nothing
    }

}
