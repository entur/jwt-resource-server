/*
 * Copyright 2022 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.entur.jwt.spring.test;

import java.io.BufferedWriter;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.entur.jwt.junit5.AuthorizationServer;
import org.entur.jwt.junit5.extention.AuthorizationServerExtension;
import org.entur.jwt.junit5.impl.AuthorizationServerImplementation;
import org.entur.jwt.junit5.impl.AuthorizationServerImplementationFactory;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.core.env.*;
import org.springframework.test.context.ContextConfigurationAttributes;
import org.springframework.test.context.ContextCustomizer;
import org.springframework.test.context.ContextCustomizerFactory;
import org.springframework.test.context.MergedContextConfiguration;

public class JwtTestContextCustomizerFactory implements ContextCustomizerFactory {

	// in-memory cache for jwks
	protected static final AuthorizationServerImplementationFactory FACTORY = AuthorizationServerExtension.getFactory();

	public static final String PROPERTY_PREFIX = "entur.jwt.tenants.";
	public static final String PROPERTY_SOURCE_NAME = "jwtJunit5Properties";

	public static final String ON_THE_FLY_PROPERTY = ".on-the-fly";

	private static final Log logger = LogFactory.getLog(JwtTestContextCustomizerFactory.class);

	private static final String prefix = "entur.jwt.tenants";

	@Override
	public ContextCustomizer createContextCustomizer(Class<?> testClass, List<ContextConfigurationAttributes> configAttributes) {
		return new TestDatabaseContextCustomizer(testClass);
	}

	static class TestDatabaseContextCustomizer implements ContextCustomizer {
		private final List<AuthorizationServerImplementation> authorizationServerImplementations;

		public TestDatabaseContextCustomizer(Class<?> testClass) {
			authorizationServerImplementations = FACTORY.create(testClass);
		}

		@Override
		public void customizeContext(ConfigurableApplicationContext context, MergedContextConfiguration mergedConfig) {
			ConfigurableEnvironment environment = context.getEnvironment();

            try {
				Map<String, Object> junit5Properties = getProperties(authorizationServerImplementations);

				// see whether issuer is populated, if not create a mock value
				// background: JWTs need an issuer, so using a list would be the easy way.
				// But configuration manipulation
				// is generally better when specifying tenants under an id key
				// This approach works around this.

				Set<String> tenants = extractTenants(junit5Properties);
				Set<String> configuredTentants = extractConfiguredTenants(environment.getPropertySources());

				if(tenants.size() == 1 && configuredTentants.size() == 1) {
					// if only one mocked and one configured tenant
					// and no name for the mocked tenant was specified (i.e. its key was created on the fly)
					// then simplyify so that the configured tenant is mocked
					String mocked = tenants.iterator().next();
					String onTheFly = (String) junit5Properties.get(mocked + ON_THE_FLY_PROPERTY);
					if(onTheFly != null && Boolean.parseBoolean(onTheFly)) {
						// mock the configured one instead
						// TODO the mocked tenant will still have the on-the-fly name within the junit5 extension
						String target = configuredTentants.iterator().next();
						for (String string : new HashSet<>(junit5Properties.keySet())) {
							if(string.startsWith(mocked)) {
								String value = (String) junit5Properties.remove(string);

								junit5Properties.put(target + string.substring(mocked.length()), value);
							}
						}
						tenants = new HashSet<>();
						tenants.add(target);
					}
				}

				for (String string : new HashSet<>(junit5Properties.keySet())) {
					if(string.endsWith(ON_THE_FLY_PROPERTY)) {
						junit5Properties.remove(string);
					}
				}
				// make sure that there is no mix of mocked and non-mocked issuers
				if(!tenants.containsAll(configuredTentants)) {
					configuredTentants.removeAll(tenants);

					logger.info("Disabling non-mocked tenants " + configuredTentants);

					// disable non-mocked tenants
					for (String tenant : configuredTentants) {
						junit5Properties.put(tenant + ".enabled", Boolean.FALSE.toString());
					}
				}

				for (String tenant : tenants) {
					String property = environment.getProperty(tenant + ".issuer");
					if (property == null) {
						// add mock issuer url
						String mockIssuer = AuthorizationServerExtension.toDefaultIssuer(tenant.substring(tenant.lastIndexOf('.') + 1));
						junit5Properties.put(tenant + ".issuer", mockIssuer);
					}
				}

				addOrReplace(environment.getPropertySources(), junit5Properties);
			} catch (IOException e) {
                throw new RuntimeException(e);
            }
        }


		private Set<String> extractTenants(Map<String, Object> junit5Properties) {
			Set<String> tenant = new HashSet<>();

			for (Map.Entry<String, Object> entry : junit5Properties.entrySet()) {

				String key = entry.getKey();
				if (key.startsWith(PROPERTY_PREFIX)) {
					int nextDot = key.indexOf('.', PROPERTY_PREFIX.length());
					if (nextDot != -1) {
						tenant.add(key.substring(0, nextDot));
					}
				}
			}

			return tenant;
		}

		private Set<String> extractConfiguredTenants(MutablePropertySources sources) {
			Set<String> tenant = new HashSet<>();

			for(PropertySource<?> propertySource : sources) {
				if(propertySource instanceof EnumerablePropertySource) {
					EnumerablePropertySource<?> epSource = (EnumerablePropertySource<?>)propertySource;

					for(String name : epSource.getPropertyNames()) {
						if (hasPropertyPrefix(name)) {
							tenant.add(parseFirstPropertyName(name));
						}
					}
				}
			}

			return tenant;
		}

		private String parseFirstPropertyName(String name) {
			int index = name.indexOf('.', PROPERTY_PREFIX.length());
			String result;
			if(index == -1) {
				result = name;
			} else {
				result = name.substring(0, index);
			}
			return result;
		}

		private boolean hasPropertyPrefix(String name) {
			return name.startsWith(PROPERTY_PREFIX) && name.length() > PROPERTY_PREFIX.length();
		}

		private void addOrReplace(MutablePropertySources propertySources, Map<String, Object> map) {
			PropertySource<?> source = propertySources.get(PROPERTY_SOURCE_NAME);
			if (source != null) {
				MapPropertySource target = (MapPropertySource) source;
				target.getSource().putAll(map);
			} else {
				MapPropertySource target = new MapPropertySource(PROPERTY_SOURCE_NAME, map);
				propertySources.addFirst(target);
			}
		}


		protected Map<String, Object> getProperties(List<AuthorizationServerImplementation> implementations) throws IOException {
			Map<String, Object> properties = new HashMap<>();
			for (int i = 0; i < implementations.size(); i++) {
				AuthorizationServerImplementation implementation = implementations.get(i);

				AuthorizationServer authorizationServer = implementation.getAuthorizationServer();

				// write certificates to temp file; get as an URI.
				// TODO do this right before the test method is called, so that
				// additional configuration parameters can be included

				// also, delete on exit, do not delete after use.
				// for certain frameworks (i.e. spring), context is reused and this
				// file might come in handy later

				String tempDir = System.getProperty("java.io.tmpdir");

				String jsonWebKeys = implementation.getJsonWebKeys();

				File tempFile = new File(tempDir, jsonWebKeys.hashCode() + ".jwk.json");
				tempFile.deleteOnExit(); // https://stackoverflow.com/questions/28752006/alternative-to-file-deleteonexit-in-java-nio
				Path path = tempFile.toPath();
				try (BufferedWriter writer = Files.newBufferedWriter(tempFile.toPath(), StandardCharsets.UTF_8)) {
					writer.write(implementation.getJsonWebKeys());
				}
				String key = authorizationServer.value();
				if (key.isEmpty()) {
					if (implementations.size() > 1) {
						throw new IllegalArgumentException("Specify authorization server id in multi-tenant tests.");
					}
					key = "mock";
					properties.put(prefix + "." + key + ON_THE_FLY_PROPERTY, "true");
				}
				properties.put(prefix + "." + key + ".jwk.location", path.toUri().toString());
			}
			return properties;
		}
	}

}
