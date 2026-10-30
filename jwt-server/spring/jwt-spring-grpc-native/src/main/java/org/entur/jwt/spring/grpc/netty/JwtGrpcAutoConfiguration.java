package org.entur.jwt.spring.grpc.netty;

import org.entur.jwt.spring.Auth0JwtAuthorityEnricher;
import org.entur.jwt.spring.DefaultJwtAuthorityEnricher;
import org.entur.jwt.spring.EnrichedJwtGrantedAuthoritiesConverter;
import org.entur.jwt.spring.JwtAuthorityEnricher;
import org.entur.jwt.spring.JwtAutoConfiguration;
import org.entur.jwt.spring.KeycloakJwtAuthorityEnricher;
import org.entur.jwt.spring.NoUserDetailsService;
import org.entur.jwt.spring.decode.ClosableJwtDecoders;
import org.entur.jwt.spring.decode.IssuerJwtDecoderFactory;
import org.entur.jwt.spring.decode.JwtHeaderToIssuerMapperDecider;
import org.entur.jwt.spring.decode.JwtHeaderToIssuerMapper;
import org.entur.jwt.spring.grpc.properties.GrpcPermitAll;
import org.entur.jwt.spring.grpc.properties.GrpcServicesConfiguration;
import org.entur.jwt.spring.grpc.properties.ServiceMatcherConfiguration;
import org.entur.jwt.spring.properties.Auth0Flavour;
import org.entur.jwt.spring.properties.Flavours;
import org.entur.jwt.spring.properties.JwtProperties;
import org.entur.jwt.spring.properties.KeycloakFlavour;
import org.entur.jwt.spring.properties.SecurityProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.grpc.server.GrpcServletRegistration;
import org.springframework.boot.grpc.server.autoconfigure.GrpcServerAutoConfiguration;
import org.springframework.boot.grpc.server.autoconfigure.security.GrpcServerOAuth2ResourceServerAutoConfiguration;
import org.springframework.boot.grpc.server.autoconfigure.security.GrpcServerSecurityAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.grpc.server.GlobalServerInterceptor;
import org.springframework.grpc.server.security.AuthenticationProcessInterceptor;
import org.springframework.grpc.server.security.GrpcSecurity;
import org.springframework.grpc.server.security.OAuth2ResourceServerConfigurer;
import org.springframework.grpc.server.security.RequestMapperConfigurer;
import org.springframework.security.config.Customizer;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Configuration
@EnableConfigurationProperties({GrpcPermitAll.class, SecurityProperties.class})
// after the gRPC server (and its security), so that the conditions on their beans work
@AutoConfigureAfter(value = {JwtAutoConfiguration.class, GrpcServerAutoConfiguration.class, GrpcServerSecurityAutoConfiguration.class})
@AutoConfigureBefore(value = {GrpcServerOAuth2ResourceServerAutoConfiguration.class})
@ConditionalOnExpression("${entur.authorization.enabled:true} || ${entur.jwt.enabled:true}")
public class JwtGrpcAutoConfiguration {

    private static final Logger LOGGER = LoggerFactory.getLogger(JwtGrpcAutoConfiguration.class);

    private final SecurityProperties securityProperties;

    private final Map<String, List<String>> permitAllMappings;

    public JwtGrpcAutoConfiguration(GrpcPermitAll permitAll, SecurityProperties securityProperties) {
        this.securityProperties = securityProperties;

        if(!securityProperties.getAuthorization().isEnabled()) {
            if(LOGGER.isInfoEnabled()) LOGGER.info("Authorization is disabled, allow anonymous access to all GRPC methods");
            permitAllMappings = Collections.emptyMap();
        } else if(permitAll.isEnabled()) {
            permitAllMappings = getPermitAllMappings(permitAll.getGrpc());
        } else {
            permitAllMappings = Collections.emptyMap();
        }
    }

    // Without the native gRPC server, there is no GrpcSecurity and so no authentication interceptor. A bean method
    // (not a nested configuration, which could be picked up by component scanning) so that it is evaluated after the
    // gRPC server auto-configuration.
    @Bean
    @ConditionalOnBean(GrpcServletRegistration.class)
    public Object grpcServletServerGuard() {
        throw new IllegalStateException("Servlet gRPC not supported by this module, use the native gRPC server. Add 'spring.grpc.server.servlet.enabled=false' or remove the gRPC servlet dependency.");
    }

    @Bean
    @ConditionalOnProperty(name = {"entur.jwt.enabled"}, havingValue = "true", matchIfMissing = true)
    public JwtOutageGrpcExceptionHandler jwtOutageGrpcExceptionHandler() {
        return new JwtOutageGrpcExceptionHandler(-1000);
    }

    @Bean
    @ConditionalOnProperty(name = {"entur.jwt.enabled"}, havingValue = "true", matchIfMissing = true)
    @ConditionalOnMissingBean(JwtAuthorityEnricher.class)
    public JwtAuthorityEnricher jwtAuthorityEnricher() {
        return new DefaultJwtAuthorityEnricher();
    }

    @Bean
    @ConditionalOnProperty(name = {"entur.jwt.enabled"}, havingValue = "true", matchIfMissing = true)
    public GrpcJwtDecoderHolder grpcJwtDecoderHolder(
            ClosableJwtDecoders closableJwtDecoders,
            ObjectProvider<JwtHeaderToIssuerMapper> jwtHeaderToIssuerMapperProvider,
            ObjectProvider<JwtHeaderToIssuerMapperDecider> jwtHeaderToIssuerMapperDeciderProvider
    ) {
        // the per-issuer decoders are shared with the web module (if present), and closed by spring
        JwtDecoder jwtDecoder = IssuerJwtDecoderFactory.create(
                closableJwtDecoders.getJwtDecoders(),
                securityProperties.getJwt().getDecode().getHeader().getMapToIssuer().isEnabled(),
                jwtHeaderToIssuerMapperProvider.getIfAvailable(),
                jwtHeaderToIssuerMapperDeciderProvider.getIfAvailable()
        );
        return new GrpcJwtDecoderHolder(jwtDecoder);
    }

    @Bean
    @GlobalServerInterceptor
    @ConditionalOnBean(GrpcSecurity.class) // i.e. not if there is no gRPC server
    @ConditionalOnProperty(name = {"entur.jwt.enabled"}, havingValue = "true", matchIfMissing = true)
    public AuthenticationProcessInterceptor authenticationProcessInterceptor(
            GrpcSecurity grpcSecurity, List<JwtAuthorityEnricher> jwtAuthorityEnrichers,
            GrpcJwtDecoderHolder grpcJwtDecoderHolder
            )
            throws Exception {
        JwtDecoder decoder = grpcJwtDecoderHolder.getJwtDecoder();
        try {
            grpcSecurity.authorizeRequests(this::authorizeRequests);

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

    @Bean
    @GlobalServerInterceptor
    @ConditionalOnBean(GrpcSecurity.class) // i.e. not if there is no gRPC server
    @ConditionalOnExpression("${entur.authorization.enabled:true} && !${entur.jwt.enabled:true}")
    public AuthenticationProcessInterceptor authenticationProcessInterceptorWithoutJwt(GrpcSecurity grpcSecurity) throws Exception {
        if(LOGGER.isInfoEnabled()) LOGGER.info("Configure without JWT");

        // no authentication, so only the permit-all methods are accessible
        grpcSecurity.authorizeRequests(this::authorizeRequests);
        return grpcSecurity.build();
    }

    private void authorizeRequests(RequestMapperConfigurer requests) {
        for (Map.Entry<String, List<String>> entry : permitAllMappings.entrySet()) {
            String service = entry.getKey();

            List<String> methods = entry.getValue();

            String[] patterns = new String[methods.size()];
            for (int i = 0; i < methods.size(); i++) {
                patterns[i] = service + '/' + methods.get(i);
            }

            requests.methods(patterns).permitAll();
        }

        if (securityProperties.getAuthorization().isEnabled()) {
            requests.allRequests().fullyAuthenticated();
        } else {
            // tokens which are present are still validated
            requests.allRequests().permitAll();
        }
    }

    private List<JwtAuthorityEnricher> getJwtAuthorityEnrichers(List<JwtAuthorityEnricher> jwtAuthorityEnrichers) {
        JwtProperties jwtProperties = securityProperties.getJwt();
        Flavours flavours = jwtProperties.getFlavours();
        if (flavours.isEnabled()) {
            List<JwtAuthorityEnricher> enrichers = new ArrayList<>(jwtAuthorityEnrichers);

            Auth0Flavour auth0 = flavours.getAuth0();
            if (auth0.isEnabled()) {
                enrichers.add(new Auth0JwtAuthorityEnricher());
            }

            KeycloakFlavour keycloak = flavours.getKeycloak();
            if (keycloak.isEnabled()) {
                enrichers.add(new KeycloakJwtAuthorityEnricher(keycloak.getClientId()));
            }

            jwtAuthorityEnrichers = enrichers;
        }
        return jwtAuthorityEnrichers;
    }

    static Map<String, List<String>> getPermitAllMappings(GrpcServicesConfiguration grpc) {
        if (!grpc.isEnabled()) {
            return Collections.emptyMap();
        }
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
                if(LOGGER.isInfoEnabled()) LOGGER.info("Allow anonymous access to all methods of GRPC service {}", configuration.getName());
            } else {
                if(LOGGER.isInfoEnabled()) LOGGER.info("Allow anonymous access to methods {} of GRPC service {}", configuration.getMethods(), configuration.getName());
            }

            // merge the methods of entries with the same service name
            List<String> serviceMethods = serviceNameMethodName.computeIfAbsent(configuration.getName(), (name) -> new ArrayList<>());
            for (String method : methods) {
                if (!serviceMethods.contains(method)) {
                    serviceMethods.add(method);
                }
            }
        }
        return serviceNameMethodName;
    }

    @Bean
    @ConditionalOnProperty(name = {"entur.jwt.enabled"}, havingValue = "true", matchIfMissing = true)
    @ConditionalOnMissingBean(UserDetailsService.class)
    public UserDetailsService userDetailsService() {
        return new NoUserDetailsService();  // avoid the default user.
    }

}
