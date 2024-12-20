package org.entur.jwt.spring.grpc.ecosystem;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import io.grpc.MethodDescriptor;
import io.grpc.ServerCall;
import net.devh.boot.grpc.server.autoconfigure.GrpcServerSecurityAutoConfiguration;
import net.devh.boot.grpc.server.security.authentication.AnonymousAuthenticationReader;
import net.devh.boot.grpc.server.security.authentication.CompositeGrpcAuthenticationReader;
import net.devh.boot.grpc.server.security.authentication.GrpcAuthenticationReader;
import net.devh.boot.grpc.server.security.check.AccessPredicate;
import net.devh.boot.grpc.server.security.check.AccessPredicateVoter;
import net.devh.boot.grpc.server.security.check.GrpcSecurityMetadataSource;
import net.devh.boot.grpc.server.security.check.ManualGrpcSecurityMetadataSource;
import org.entur.jwt.spring.Auth0JwtAuthorityEnricher;
import org.entur.jwt.spring.DefaultJwtAuthorityEnricher;
import org.entur.jwt.spring.EnrichedJwtGrantedAuthoritiesConverter;
import org.entur.jwt.spring.JwkSourceMap;
import org.entur.jwt.spring.JwtAuthorityEnricher;
import org.entur.jwt.spring.JwtAutoConfiguration;
import org.entur.jwt.spring.KeycloakJwtAuthorityEnricher;
import org.entur.jwt.spring.NoUserDetailsService;
import org.entur.jwt.spring.grpc.IssuerAuthenticationProvider;
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
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.vote.UnanimousBased;
import org.springframework.security.authentication.AnonymousAuthenticationProvider;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtIssuerValidator;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationProvider;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Configuration
@EnableConfigurationProperties({GrpcPermitAll.class, Flavours.class, GrpcExceptionHandlers.class})
@AutoConfigureAfter(value = {JwtAutoConfiguration.class})
@AutoConfigureBefore(value = {GrpcServerSecurityAutoConfiguration.class, SecurityAutoConfiguration.class})
public class GrpcEcosystemAutoConfiguration {

    // TODO spring factory for all sort of exception handling logging
    // currently we only support two types

    private static Logger log = LoggerFactory.getLogger(GrpcEcosystemAutoConfiguration.class);

    @Bean
    @ConditionalOnProperty(name = {"entur.jwt.enabled"}, havingValue = "true", matchIfMissing = true)
    @ConditionalOnMissingBean(JwtAuthorityEnricher.class)
    public JwtAuthorityEnricher jwtAuthorityEnricher() {
        return new DefaultJwtAuthorityEnricher();
    }

    @Bean
    @ConditionalOnMissingBean(JwtExceptionTranslatingServerInterceptor.class)
    public JwtExceptionTranslatingServerInterceptor extendedExceptionTranslatingServerInterceptor() {
        return new JwtExceptionTranslatingServerInterceptor();
    }

    @Bean
    @ConditionalOnMissingBean(GrpcAuthenticationReader.class)
    public GrpcAuthenticationReader authenticationReader() {
        final List<GrpcAuthenticationReader> readers = new ArrayList<>();
        readers.add(new MustBeBearerIfPresentAuthenticationReader(accessToken -> new BearerTokenAuthenticationToken(accessToken)));
        // anon auth as found in spring security's use of AnonymousAuthenticationToken
        readers.add(new AnonymousAuthenticationReader("key","anonymous", AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS")));
        return new CompositeGrpcAuthenticationReader(readers);
    }

    @Bean
    @ConditionalOnExpression("${entur.jwt.enabled:true}")
    public GrpcSecurityMetadataSource grpcSecurityMetadataSource(GrpcPermitAll permitAll) {
        final ManualGrpcSecurityMetadataSource source = new ManualGrpcSecurityMetadataSource();

        AccessPredicate defaultAccessPredicate = AccessPredicate.fullyAuthenticated();

        if (permitAll.isActive()) {
            GrpcServicesConfiguration grpc = permitAll.getGrpc();

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

            if(!serviceNameMethodName.isEmpty()) {
                defaultAccessPredicate = new AccessPredicate() {
                    @Override
                    public boolean test(Authentication authentication, ServerCall<?, ?> serverCall) {
                        MethodDescriptor<?, ?> method = serverCall.getMethodDescriptor();

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

                        if (methodNames.contains(lowerCaseBareMethodName) || methodNames.contains(lowerCaseFullMethodName)) {
                            return true;
                        }

                        return AccessPredicate.fullyAuthenticated().test(authentication, serverCall);
                    }
                };
            }
        }

        source.setDefault(defaultAccessPredicate);

        return source;
    }

    @Bean
    public AccessDecisionManager accessDecisionManager() { // so that grpcSecurityMetadataSource takes effect, see docs
        final List<AccessDecisionVoter<?>> voters = new ArrayList<>();
        voters.add(new AccessPredicateVoter());
        return new UnanimousBased(voters);
    }

    @Bean
    @ConditionalOnMissingBean(IssuerAuthenticationProvider.class)
    public IssuerAuthenticationProvider issuerAuthenticationProvider(JwkSourceMap jwkSourceMap, List<JwtAuthorityEnricher> jwtAuthorityEnrichers, List<OAuth2TokenValidator<Jwt>> jwtValidators, Flavours flavours) {
        log.info("Configure Grpc security");

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
            nimbusJwtDecoder.setJwtValidator(getJwtValidators(entry.getKey(), jwtValidators));

            JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();

            jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(new EnrichedJwtGrantedAuthoritiesConverter(jwtAuthorityEnrichers));

            JwtAuthenticationProvider authenticationProvider = new JwtAuthenticationProvider(nimbusJwtDecoder);
            authenticationProvider.setJwtAuthenticationConverter(jwtAuthenticationConverter);

            map.put(entry.getKey(), authenticationProvider);
        }

        return new IssuerAuthenticationProvider(map);
    }

    private DelegatingOAuth2TokenValidator<Jwt> getJwtValidators(String issuer, List<OAuth2TokenValidator<Jwt>> jwtValidators) {
        List<OAuth2TokenValidator<Jwt>> validators = new ArrayList<>();
        validators.add(new JwtIssuerValidator(issuer)); // this check is implicit, but lets add it regardless
        validators.addAll(jwtValidators);
        DelegatingOAuth2TokenValidator<Jwt> validator = new DelegatingOAuth2TokenValidator<>(validators);
        return validator;
    }

    @Bean
    public AuthenticationManager authenticationManager(IssuerAuthenticationProvider provider) {
        final List<AuthenticationProvider> providers = new ArrayList<>();
        providers.add(provider);
        providers.add(new AnonymousAuthenticationProvider("key"));
        return new ProviderManager(providers);
    }

    @Bean
    @ConditionalOnProperty(name = {"entur.jwt.enabled"}, havingValue = "true", matchIfMissing = true)
    @ConditionalOnMissingBean(UserDetailsService.class)
    public UserDetailsService userDetailsService() {
        return new NoUserDetailsService();  // avoid the default user.
    }

}
