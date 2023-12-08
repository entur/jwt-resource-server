package org.entur.jwt.spring.grpc;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import org.entur.jwt.spring.*;
import org.entur.jwt.spring.grpc.properties.GrpcPermitAll;
import org.entur.jwt.spring.grpc.properties.GrpcServicesConfiguration;
import org.entur.jwt.spring.grpc.properties.ServiceMatcherConfiguration;
import org.entur.jwt.spring.properties.Auth0Flavour;
import org.entur.jwt.spring.properties.Flavours;
import org.entur.jwt.spring.properties.JwtProperties;
import org.entur.jwt.spring.properties.KeycloakFlavour;
import org.lognet.springboot.grpc.GRpcErrorHandler;
import org.lognet.springboot.grpc.autoconfigure.ConditionalOnMissingErrorHandler;
import org.lognet.springboot.grpc.autoconfigure.security.SecurityAutoConfiguration;
import org.lognet.springboot.grpc.recovery.ErrorHandlerAdapter;
import org.lognet.springboot.grpc.recovery.GRpcExceptionHandler;
import org.lognet.springboot.grpc.recovery.GRpcExceptionScope;
import org.lognet.springboot.grpc.recovery.GRpcServiceAdvice;
import org.lognet.springboot.grpc.security.GrpcSecurity;
import org.lognet.springboot.grpc.security.GrpcSecurityConfigurerAdapter;
import org.lognet.springboot.grpc.security.GrpcServiceAuthorizationConfigurer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.JwtIssuerValidator;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationProvider;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

@Configuration
@EnableConfigurationProperties({GrpcPermitAll.class, Flavours.class})
@AutoConfigureAfter(value = {JwtAutoConfiguration.class})
@AutoConfigureBefore(value = {org.lognet.springboot.grpc.autoconfigure.GRpcAutoConfiguration.class, SecurityAutoConfiguration.class})
public class GrpcAutoConfiguration {

    private static Logger log = LoggerFactory.getLogger(GrpcAutoConfiguration.class);


    @Bean
    @ConditionalOnProperty(name = {"entur.jwt.enabled"}, havingValue = "true", matchIfMissing = true)
    @ConditionalOnMissingBean(JwtAuthorityEnricher.class)
    public JwtAuthorityEnricher jwtAuthorityEnricher() {
        return new DefaultJwtAuthorityEnricher();
    }

    @Configuration
    @ConditionalOnExpression("${entur.jwt.enabled:true}")
    public static class GrpcSecurityConfiguration extends GrpcSecurityConfigurerAdapter {

        private JwkSourceMap jwkSourceMap;

        private List<JwtAuthorityEnricher> jwtAuthorityEnrichers;

        private List<OAuth2TokenValidator<Jwt>> jwtValidators;

        private GrpcPermitAll permitAll;
        private Flavours flavours;

        public GrpcSecurityConfiguration(JwkSourceMap jwkSourceMap, List<JwtAuthorityEnricher> jwtAuthorityEnrichers, List<OAuth2TokenValidator<Jwt>> jwtValidators, GrpcPermitAll permitAll, Flavours flavours) {
            this.jwkSourceMap = jwkSourceMap;
            this.jwtAuthorityEnrichers = jwtAuthorityEnrichers;
            this.jwtValidators = jwtValidators;
            this.permitAll = permitAll;
            this.flavours = flavours;
        }

        @Override
        public void configure(GrpcSecurity grpcSecurity) throws Exception {
            log.info("Configure Grpc security");

            if (permitAll.isActive()) {
                configureGrpcServiceMethodFilter(permitAll.getGrpc(), grpcSecurity);
            } else {
                // default to authenticated
                grpcSecurity.authorizeRequests().anyMethod().authenticated();
            }

            List<JwtAuthorityEnricher> jwtAuthorityEnrichers = this.jwtAuthorityEnrichers;
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

            Map<String, JWKSource> jwkSources = jwkSourceMap.getJwkSources();

            Map<String, AuthenticationProvider> map = new HashMap<>(jwkSources.size() * 4);

            for (Map.Entry<String, JWKSource> entry : jwkSources.entrySet()) {
                JWKSource jwkSource = entry.getValue();

                DefaultJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
                JWSVerificationKeySelector keySelector = new JWSVerificationKeySelector(JWSAlgorithm.Family.SIGNATURE, jwkSource);
                jwtProcessor.setJWSKeySelector(keySelector);

                NimbusJwtDecoder nimbusJwtDecoder = new NimbusJwtDecoder(jwtProcessor);
                nimbusJwtDecoder.setJwtValidator(getJwtValidators(entry.getKey()));

                JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();

                jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(new EnrichedJwtGrantedAuthoritiesConverter(jwtAuthorityEnrichers));

                JwtAuthenticationProvider authenticationProvider = new JwtAuthenticationProvider(nimbusJwtDecoder);
                authenticationProvider.setJwtAuthenticationConverter(jwtAuthenticationConverter);

                map.put(entry.getKey(), authenticationProvider);
            }

            grpcSecurity.authenticationProvider(new IssuerAuthenticationProvider(map));
        }

        private void configureGrpcServiceMethodFilter(GrpcServicesConfiguration grpc, GrpcSecurity grpcSecurity) throws Exception {
            GrpcServiceAuthorizationConfigurer.Registry registry = grpcSecurity.authorizeRequests();

            Map<String, List<String>> serviceNameMethodName = new HashMap<>();
            for (ServiceMatcherConfiguration configuration : grpc.getServices()) {
                if (!configuration.isEnabled()) {
                    continue;
                }

                List<String> methods = configuration.getMethods();

                if (methods.contains("*")) {
                    log.info("Allow anonymous access to all methods of GRPC service " + configuration.getName());
                } else {
                    log.info("Allow anonymous access to methods " + configuration.getMethods() + " of GRPC service " + configuration.getName());
                }
                List<String> lowercaseMethodNames = new ArrayList<>();

                for (String method : methods) {
                    lowercaseMethodNames.add(method.toLowerCase());
                }

                serviceNameMethodName.put(configuration.getName().toLowerCase(), lowercaseMethodNames);
            }

            // service name is included in method name
            registry.anyMethodExcluding((method) -> {
                String lowerCaseServiceName = method.getServiceName().toLowerCase();
                List<String> methodNames = serviceNameMethodName.get(lowerCaseServiceName);
                if (methodNames == null) {
                    return false;
                }

                if (methodNames.contains("*")) {
                    return true;
                }

                String lowerCaseBareMethodName = method.getBareMethodName().toLowerCase();
                String lowerCaseFullMethodName = method.getFullMethodName().toLowerCase();

                return methodNames.contains(lowerCaseBareMethodName) || methodNames.contains(lowerCaseFullMethodName);
            }).authenticated();
        }

        private DelegatingOAuth2TokenValidator<Jwt> getJwtValidators(String issuer) {
            List<OAuth2TokenValidator<Jwt>> validators = new ArrayList<>();
            validators.add(new JwtIssuerValidator(issuer)); // this check is implicit, but lets add it regardless
            validators.addAll(jwtValidators);
            DelegatingOAuth2TokenValidator<Jwt> validator = new DelegatingOAuth2TokenValidator<>(validators);
            return validator;
        }
    }

    @Bean
    @ConditionalOnProperty(name = {"entur.jwt.enabled"}, havingValue = "true", matchIfMissing = true)
    @ConditionalOnMissingBean(UserDetailsService.class)
    public UserDetailsService userDetailsService() {
        return new NoUserDetailsService();  // avoid the default user.
    }

    @ConditionalOnMissingErrorHandler(AuthenticationException.class)
    @Configuration
    static class DefaultAuthErrorHandlerConfiguration {

        @GRpcServiceAdvice
        public static class DefaultAuthErrorHandler extends ErrorHandlerAdapter {
            public DefaultAuthErrorHandler(Optional<GRpcErrorHandler> errorHandler) {
                super(errorHandler);
            }

            @GRpcExceptionHandler
            public Status handle(AuthenticationException e, GRpcExceptionScope scope) {
                if (e instanceof AuthenticationServiceException) {
                    Throwable cause1 = e.getCause();
                    if (cause1 instanceof JwtException) {
                        Throwable cause2 = cause1.getCause();
                        if (cause2 instanceof KeySourceException) {
                            return handle(e, Status.UNAVAILABLE, scope);
                        }
                    }
                }
                return handle(e, Status.UNAUTHENTICATED, scope);
            }
        }
    }


    @ConditionalOnMissingErrorHandler(StatusRuntimeException.class)
    @Configuration
    static class DefaultStatusErrorHandlerConfiguration {
        @GRpcServiceAdvice
        public static class StatusErrorHandler extends ErrorHandlerAdapter {
            public StatusErrorHandler(Optional<GRpcErrorHandler> errorHandler) {
                super(errorHandler);
            }

            @GRpcExceptionHandler
            public Status handle(StatusRuntimeException e, GRpcExceptionScope scope) {
                return handle(e, e.getStatus(), scope);
            }
        }
    }

}
