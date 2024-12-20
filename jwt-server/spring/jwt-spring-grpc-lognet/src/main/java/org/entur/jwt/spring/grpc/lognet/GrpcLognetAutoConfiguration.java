package org.entur.jwt.spring.grpc.lognet;

import com.nimbusds.jose.KeySourceException;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import org.entur.jwt.spring.Auth0JwtAuthorityEnricher;
import org.entur.jwt.spring.DefaultJwtAuthorityEnricher;
import org.entur.jwt.spring.JwkSourceMap;
import org.entur.jwt.spring.JwtAuthorityEnricher;
import org.entur.jwt.spring.JwtAutoConfiguration;
import org.entur.jwt.spring.KeycloakJwtAuthorityEnricher;
import org.entur.jwt.spring.NoUserDetailsService;
import org.entur.jwt.spring.grpc.IssuerAuthenticationProvider;
import org.entur.jwt.spring.grpc.lognet.annotate.ConditionalOnMissingErrorHandlerForExactException;
import org.entur.jwt.spring.grpc.properties.GrpcException;
import org.entur.jwt.spring.grpc.properties.GrpcExceptionHandlers;
import org.entur.jwt.spring.grpc.properties.GrpcPermitAll;
import org.entur.jwt.spring.grpc.properties.GrpcServicesConfiguration;
import org.entur.jwt.spring.grpc.properties.ServiceMatcherConfiguration;
import org.entur.jwt.spring.properties.Auth0Flavour;
import org.entur.jwt.spring.properties.Flavours;
import org.entur.jwt.spring.properties.KeycloakFlavour;
import org.lognet.springboot.grpc.autoconfigure.security.SecurityAutoConfiguration;
import org.lognet.springboot.grpc.recovery.GRpcExceptionHandler;
import org.lognet.springboot.grpc.recovery.GRpcExceptionScope;
import org.lognet.springboot.grpc.recovery.GRpcServiceAdvice;
import org.lognet.springboot.grpc.security.GrpcSecurity;
import org.lognet.springboot.grpc.security.GrpcSecurityConfigurerAdapter;
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
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtException;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Configuration
@EnableConfigurationProperties({GrpcPermitAll.class, Flavours.class, GrpcExceptionHandlers.class})
@AutoConfigureAfter(value = {JwtAutoConfiguration.class})
@AutoConfigureBefore(value = {org.lognet.springboot.grpc.autoconfigure.GRpcAutoConfiguration.class, SecurityAutoConfiguration.class})
public class GrpcLognetAutoConfiguration {

    // TODO spring factory for all sort of exception handling logging
    // currently we only support two types

    private static Logger log = LoggerFactory.getLogger(GrpcLognetAutoConfiguration.class);


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

            IssuerAuthenticationProvider provider = IssuerAuthenticationProvider.newBuilder()
                    .withJwkSourceMap(jwkSourceMap)
                    .withJwtValidators(jwtValidators)
                    .withJwtAuthorityEnrichers(jwtAuthorityEnrichers)
                    .build();

            grpcSecurity.authenticationProvider(provider);
        }

        private void configureGrpcServiceMethodFilter(GrpcServicesConfiguration grpc, GrpcSecurity grpcSecurity) throws Exception {
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
            grpcSecurity.authorizeRequests().anyMethodExcluding((method) -> {
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

    }

    @Bean
    @ConditionalOnProperty(name = {"entur.jwt.enabled"}, havingValue = "true", matchIfMissing = true)
    @ConditionalOnMissingBean(UserDetailsService.class)
    public UserDetailsService userDetailsService() {
        return new NoUserDetailsService();  // avoid the default user.
    }

    @ConditionalOnMissingErrorHandlerForExactException(AuthenticationException.class)
    @Configuration
    static class DefaultAuthErrorHandlerConfiguration {

        @GRpcServiceAdvice
        public static class DefaultAuthErrorHandler {

            private GrpcErrorLogger logger;

            public DefaultAuthErrorHandler(GrpcExceptionHandlers grpcExceptionHandlers) {
                super();

                GrpcException grpcException = grpcExceptionHandlers.find(AuthenticationException.class);
                this.logger = new GrpcErrorLogger(DefaultAuthErrorHandler.class.getName(), grpcException.getLog().getLevel(), grpcException.getLog().isStackTrace());
            }

            @GRpcExceptionHandler
            public Status handle(AuthenticationException e, GRpcExceptionScope scope) {
                if (e instanceof AuthenticationServiceException) {
                    Throwable cause1 = e.getCause();
                    if (cause1 instanceof JwtException) {
                        Throwable cause2 = cause1.getCause();
                        if (cause2 instanceof KeySourceException) {
                            logger.handle(e, Status.UNAVAILABLE, scope);

                            return Status.UNAVAILABLE.withDescription(e.getMessage());
                        }
                    }
                }
                logger.handle(e, Status.UNAUTHENTICATED, scope);

                return Status.UNAUTHENTICATED.withDescription(e.getMessage());
            }
        }
    }

    @ConditionalOnMissingErrorHandlerForExactException(StatusRuntimeException.class)
    @Configuration
    static class DefaultStatusErrorHandlerConfiguration {
        @GRpcServiceAdvice
        public static class StatusErrorHandler {
            private static final org.slf4j.Logger log =
                    org.slf4j.LoggerFactory.getLogger(StatusErrorHandler.class);

            public StatusErrorHandler() {
                super();

            }

            @GRpcExceptionHandler
            public Status handle(StatusRuntimeException e, GRpcExceptionScope scope) {

                Status status = e.getStatus();
                if(status == Status.INTERNAL) {
                    log.error("Got error with status " + status.getCode().name(), e);
                } else {
                    log.info("Got error with status " + status.getCode().name(), e);
                }

                return status.withDescription(e.getMessage());
            }
        }
    }

    @ConditionalOnMissingErrorHandlerForExactException(AccessDeniedException.class)
    @Configuration
    static class DefaultAccessDeniedErrorHandlerConfig {

        @GRpcServiceAdvice
        public static class DefaultAccessDeniedErrorHandler {

            private GrpcErrorLogger logger;
            @java.lang.SuppressWarnings("all")
            public DefaultAccessDeniedErrorHandler(GrpcExceptionHandlers grpcExceptionHandlers) {
                super();

                GrpcException grpcException = grpcExceptionHandlers.find(AccessDeniedException.class);
                this.logger = new GrpcErrorLogger(DefaultAccessDeniedErrorHandler.class.getName(), grpcException.getLog().getLevel(), grpcException.getLog().isStackTrace());
            }

            @GRpcExceptionHandler
            public Status handle(AccessDeniedException e, GRpcExceptionScope scope) {
                logger.handle(e, Status.PERMISSION_DENIED, scope);

                return Status.PERMISSION_DENIED.withDescription(e.getMessage());
            }
        }
    }


}
