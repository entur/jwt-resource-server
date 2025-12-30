package org.entur.jwt.spring.grpc.netty;

import org.entur.jwt.spring.Auth0JwtAuthorityEnricher;
import org.entur.jwt.spring.DefaultJwtAuthorityEnricher;
import org.entur.jwt.spring.EnrichedJwtGrantedAuthoritiesConverter;
import org.entur.jwt.spring.JwkSourceMap;
import org.entur.jwt.spring.JwtAuthorityEnricher;
import org.entur.jwt.spring.JwtAutoConfiguration;
import org.entur.jwt.spring.KeycloakJwtAuthorityEnricher;
import org.entur.jwt.spring.NoUserDetailsService;
import org.entur.jwt.spring.grpc.properties.GrpcExceptionHandlers;
import org.entur.jwt.spring.grpc.properties.GrpcPermitAll;
import org.entur.jwt.spring.grpc.properties.GrpcServicesConfiguration;
import org.entur.jwt.spring.grpc.properties.ServiceMatcherConfiguration;
import org.entur.jwt.spring.properties.Auth0Flavour;
import org.entur.jwt.spring.properties.Flavours;
import org.entur.jwt.spring.properties.KeycloakFlavour;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.grpc.server.autoconfigure.ConditionalOnGrpcServletServer;
import org.springframework.boot.grpc.server.autoconfigure.security.OAuth2ResourceServerAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.grpc.server.GlobalServerInterceptor;
import org.springframework.grpc.server.security.AuthenticationProcessInterceptor;
import org.springframework.grpc.server.security.GrpcSecurity;
import org.springframework.grpc.server.security.OAuth2ResourceServerConfigurer;
import org.springframework.security.config.Customizer;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Configuration
@EnableConfigurationProperties({GrpcPermitAll.class, Flavours.class, GrpcExceptionHandlers.class})
@AutoConfigureAfter(value = {JwtAutoConfiguration.class})
@AutoConfigureBefore(value = {OAuth2ResourceServerAutoConfiguration.class})
@ConditionalOnProperty(name = {"entur.jwt.enabled"}, havingValue = "true", matchIfMissing = true)
public class JwtGrpcAutoConfiguration {

    private static final Logger LOGGER = LoggerFactory.getLogger(JwtGrpcAutoConfiguration.class);

    private JwkSourceMap jwkSourceMap;

    private List<OAuth2TokenValidator<Jwt>> jwtValidators;

    private Flavours flavours;

    private final Map<String, List<String>> permitAllMappings;

    public JwtGrpcAutoConfiguration(JwkSourceMap jwkSourceMap, List<OAuth2TokenValidator<Jwt>> jwtValidators, GrpcPermitAll permitAll, Flavours flavours) {
        this.jwkSourceMap = jwkSourceMap;
        this.jwtValidators = jwtValidators;
        this.flavours = flavours;

        if(permitAll.isEnabled()) {
            permitAllMappings = getPermitAllMappings(permitAll.getGrpc());
        } else {
            permitAllMappings = Collections.emptyMap();
        }
    }

    @Configuration
    @ConditionalOnGrpcServletServer
    public static class GrpcServletServerGuard {

        public GrpcServletServerGuard() {
            throw new IllegalStateException("Servlet gRPC not supported by this module");
        }
    }


    @Bean
    public JwtOutageGrpcExceptionHandler jwtOutageGrpcExceptionHandler() {
        return new JwtOutageGrpcExceptionHandler(-1000);
    }

    @Bean
    @ConditionalOnMissingBean(JwtAuthorityEnricher.class)
    public JwtAuthorityEnricher jwtAuthorityEnricher() {
        return new DefaultJwtAuthorityEnricher();
    }

    @Bean
    @GlobalServerInterceptor
    public AuthenticationProcessInterceptor jwtSecurityFilterChain(GrpcSecurity grpcSecurity, List<JwtAuthorityEnricher> jwtAuthorityEnrichers) throws Exception {
        try {
            grpcSecurity.authorizeRequests((requests) -> {

                for (Map.Entry<String, List<String>> entry : permitAllMappings.entrySet()) {
                    String service = entry.getKey();

                    List<String> methods = entry.getValue();

                    String[] patterns = new String[methods.size()];
                    for (int i = 0; i < methods.size(); i++) {
                        patterns[i] = service + '/' + methods.get(i);
                    }
                    LOGGER.info(Arrays.toString(patterns));
                    requests.methods(patterns).permitAll();
                }

                requests.allRequests().fullyAuthenticated();
            });

            IssuerJwtDecoder decoder = IssuerJwtDecoder.newBuilder()
                    .withJwkSourceMap(jwkSourceMap)
                    .withJwtValidators(jwtValidators)
                    .build();

            Customizer<OAuth2ResourceServerConfigurer.JwtConfigurer> configurer = new Customizer<OAuth2ResourceServerConfigurer.JwtConfigurer>() {
                @Override
                public void customize(OAuth2ResourceServerConfigurer.JwtConfigurer jwtConfigurer) {
                    JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
                    jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(new EnrichedJwtGrantedAuthoritiesConverter(getJwtAuthorityEnrichers(jwtAuthorityEnrichers)));

                    jwtConfigurer.decoder(decoder);
                    jwtConfigurer.jwtAuthenticationConverter(jwtAuthenticationConverter);
                }
            };
            grpcSecurity.oauth2ResourceServer((resourceServer) -> resourceServer.jwt(configurer));
            return grpcSecurity.build();
        } catch(Exception e) {
            throw new RuntimeException(e);
        }
    }

    private List<JwtAuthorityEnricher> getJwtAuthorityEnrichers(List<JwtAuthorityEnricher> jwtAuthorityEnrichers) {
        if (flavours.isEnabled()) {
            List<JwtAuthorityEnricher> enrichers = new ArrayList<>(jwtAuthorityEnrichers);

            Auth0Flavour auth0 = flavours.getAuth0();
            if (auth0.isEnabled()) {
                enrichers.add(new Auth0JwtAuthorityEnricher());
            }

            KeycloakFlavour keycloak = flavours.getKeycloak();
            if (keycloak.isEnabled()) {
                enrichers.add(new KeycloakJwtAuthorityEnricher());
            }

            jwtAuthorityEnrichers = enrichers;
        }
        return jwtAuthorityEnrichers;
    }

    private static Map<String, List<String>> getPermitAllMappings(GrpcServicesConfiguration grpc) {
        Map<String, List<String>> serviceNameMethodName = new HashMap<>();
        for (ServiceMatcherConfiguration configuration : grpc.getServices()) {
            if (!configuration.isEnabled()) {
                continue;
            }

            List<String> methods = configuration.getMethods();
            if(methods.isEmpty()) {
                continue;
            }

            if (methods.contains("*")) {
                LOGGER.info("Allow anonymous access to all methods of GRPC service " + configuration.getName());
            } else {
                LOGGER.info("Allow anonymous access to methods " + configuration.getMethods() + " of GRPC service " + configuration.getName());
            }

            serviceNameMethodName.put(configuration.getName(), methods);
        }
        return serviceNameMethodName;
    }

    @Bean
    @ConditionalOnMissingBean(UserDetailsService.class)
    public UserDetailsService userDetailsService() {
        return new NoUserDetailsService();  // avoid the default user.
    }

}
