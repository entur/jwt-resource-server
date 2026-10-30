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

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

/**
 * Writes the authorization servers to a properties file.
 * <br><br>
 * Test classes might run in parallel, so the file is shared: the first test class in this JVM replaces the
 * file (i.e. from a previous run), later test classes add their authorization servers to it. If authorization
 * servers with different keys use the same id, the published keys of that id include the keys of both.
 */

public class PropertiesFileResourceServerConfigurationEnricher extends AbstractPropertiesResourceServerConfigurationEnricher {

    private static final JsonMapper JSON_MAPPER = JsonMapper.builder().build();

    private static final String JWK_LOCATION_PROPERTY = ".jwk.location";

    // guards reading and writing the output files of this JVM
    private static final Object LOCK = new Object();

    // output files already written by this JVM
    private static final Set<Path> WRITTEN = new HashSet<>();

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
        Map<String, Object> properties = getProperties(authorizationServers);

        // add the issuers, as read by PropertiesFileAuthorizationServerConfigurationResolver
        for (AuthorizationServerImplementation authorizationServer : authorizationServers) {
            String tenant = authorizationServer.getId().isEmpty() ? AuthorizationServerImplementationFactory.ON_THE_FLY_TENANT : authorizationServer.getId();

            properties.put(prefix + "." + tenant + ".issuer", AuthorizationServerExtension.toIssuer(authorizationServer.getAuthorizationServer()));
        }

        synchronized (LOCK) {
            Path path = output.toAbsolutePath().normalize();

            Properties p = new Properties();
            if (!WRITTEN.add(path) && Files.exists(path)) {
                try (InputStream in = Files.newInputStream(path)) {
                    p.load(in);
                }
            }

            for (Map.Entry<String, Object> e : properties.entrySet()) {
                String value = e.getValue().toString();
                if (e.getKey().endsWith(JWK_LOCATION_PROPERTY)) {
                    String existing = p.getProperty(e.getKey());
                    if (existing != null && !existing.equals(value)) {
                        value = mergeJsonWebKeys(existing, value);
                    }
                }
                p.put(e.getKey(), value);
            }

            StringWriter writer = new StringWriter();
            p.store(writer, null);
            AuthorizationServerImplementationFactory.writeAtomically(path, writer.toString());
        }
    }

    /**
     * Merge the keys of two JWK set files, i.e. of authorization servers with the same id.
     *
     * @param location JWK set file location
     * @param otherLocation other JWK set file location
     * @return location of a JWK set file with the keys of both
     * @throws IOException if the merged file could not be written
     */

    protected String mergeJsonWebKeys(String location, String otherLocation) throws IOException {
        Path path = Paths.get(URI.create(location));
        if (!Files.exists(path)) {
            return otherLocation;
        }
        Set<JsonNode> keys = new LinkedHashSet<>();
        for (String l : new String[] {location, otherLocation}) {
            JsonNode jwks = JSON_MAPPER.readTree(Files.readString(Paths.get(URI.create(l)), StandardCharsets.UTF_8));
            for (JsonNode key : jwks.path("keys")) {
                keys.add(key);
            }
        }
        ObjectNode merged = JSON_MAPPER.createObjectNode();
        ArrayNode array = merged.putArray("keys");
        keys.forEach(array::add);

        String content = JSON_MAPPER.writeValueAsString(merged);
        File file = new File(System.getProperty("java.io.tmpdir"), content.hashCode() + ".jwk.json");
        file.deleteOnExit();
        AuthorizationServerImplementationFactory.writeAtomically(file.toPath(), content);
        return file.toPath().toUri().toString();
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
