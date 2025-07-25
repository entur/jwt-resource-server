package org.entur.jwt.spring.grpc.ecosystem;

import net.devh.boot.grpc.common.util.InterceptorOrder;
import net.devh.boot.grpc.server.autoconfigure.GrpcServerSecurityAutoConfiguration;
import net.devh.boot.grpc.server.interceptor.GrpcGlobalServerInterceptor;
import net.devh.boot.grpc.server.security.authentication.CompositeGrpcAuthenticationReader;
import net.devh.boot.grpc.server.security.authentication.GrpcAuthenticationReader;
import net.devh.boot.grpc.server.security.check.AccessPredicate;
import net.devh.boot.grpc.server.security.check.AccessPredicateVoter;
import net.devh.boot.grpc.server.security.check.GrpcSecurityMetadataSource;
import net.devh.boot.grpc.server.security.check.ManualGrpcSecurityMetadataSource;
import org.entur.jwt.spring.Auth0JwtAuthorityEnricher;
import org.entur.jwt.spring.DefaultJwtAuthorityEnricher;
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
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthenticationToken;

import java.util.*;

@Configuration
@EnableConfigurationProperties({GrpcPermitAll.class, Flavours.class, GrpcExceptionHandlers.class})
@AutoConfigureAfter(value = {JwtAutoConfiguration.class})
@AutoConfigureBefore(value = {GrpcServerSecurityAutoConfiguration.class, SecurityAutoConfiguration.class})
@ConditionalOnProperty(name = {"entur.jwt.enabled"}, havingValue = "true", matchIfMissing = true)
public class GrpcEcosystemAutoConfiguration {

    private static Logger log = LoggerFactory.getLogger(GrpcEcosystemAutoConfiguration.class);

    private final Map<String, List<String>> permitAllMappings;

    public GrpcEcosystemAutoConfiguration(GrpcPermitAll permitAll) {
        if(permitAll.isEnabled()) {
            permitAllMappings = getPermitAllMappings(permitAll.getGrpc());
        } else {
            permitAllMappings = Collections.emptyMap();
        }
    }

    @Bean
    @ConditionalOnMissingBean(JwtAuthorityEnricher.class)
    public JwtAuthorityEnricher jwtAuthorityEnricher() {
        return new DefaultJwtAuthorityEnricher();
    }

    @Bean
    @ConditionalOnMissingBean(JwtExceptionTranslatingServerInterceptor.class)
    @GrpcGlobalServerInterceptor
    public JwtExceptionTranslatingServerInterceptor extendedExceptionTranslatingServerInterceptor() {
        return new JwtExceptionTranslatingServerInterceptor(InterceptorOrder.ORDER_SECURITY_EXCEPTION_HANDLING + 1);
    }

    @Bean
    @ConditionalOnMissingBean(GrpcAuthenticationReader.class)
    public GrpcAuthenticationReader authenticationReader(GrpcPermitAll permitAll) {
        MustBeBearerIfPresentAuthenticationReader mustBeBearerIfPresentAuthenticationReader = new MustBeBearerIfPresentAuthenticationReader(accessToken -> new BearerTokenAuthenticationToken(accessToken));
        if(permitAllMappings.isEmpty()) {
            return mustBeBearerIfPresentAuthenticationReader;
        }

        final List<GrpcAuthenticationReader> readers = new ArrayList<>();
        readers.add(mustBeBearerIfPresentAuthenticationReader);
        // anon auth as found in spring security's use of AnonymousAuthenticationToken
        readers.add(new MustBePermitAllAnonymousAuthenticationReader("key", "anonymous", AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS"), permitAllMappings));
        return new CompositeGrpcAuthenticationReader(readers);
    }

    @Bean
    @ConditionalOnMissingBean(GrpcSecurityMetadataSource.class)
    public GrpcSecurityMetadataSource grpcSecurityMetadataSource(GrpcPermitAll permitAll) {
        final ManualGrpcSecurityMetadataSource source = new ManualGrpcSecurityMetadataSource();

        AccessPredicate defaultAccessPredicate = AccessPredicate.fullyAuthenticated();

        if (!permitAllMappings.isEmpty()) {
            defaultAccessPredicate = new MustBePermitAllAnonymousOrFullyAuthenticatedAccessPredicate(permitAllMappings);
        }

        source.setDefault(defaultAccessPredicate);

        return source;
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
        return serviceNameMethodName;
    }

    @Bean
    @ConditionalOnMissingBean(AccessDecisionManager.class)
    public AccessDecisionManager accessDecisionManager() { // so that grpcSecurityMetadataSource takes effect, see docs
        final List<AccessDecisionVoter<?>> voters = new ArrayList<>();
        voters.add(new AccessPredicateVoter());
        return new UnanimousBased(voters);
    }

    @Bean
    @ConditionalOnMissingBean(AuthenticationManager.class)
    public AuthenticationManager authenticationManager(JwkSourceMap jwkSourceMap, List<JwtAuthorityEnricher> jwtAuthorityEnrichers, List<OAuth2TokenValidator<Jwt>> jwtValidators, Flavours flavours) {

        if(log.isDebugEnabled()) log.debug("Configure GRPC security");

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

        final List<AuthenticationProvider> providers = new ArrayList<>();
        providers.add(provider);

        if (!permitAllMappings.isEmpty()) {
            providers.add(new AnonymousAuthenticationProvider("key"));
        }

        return new ProviderManager(providers);
    }

    @Bean
    @ConditionalOnMissingBean(UserDetailsService.class)
    public UserDetailsService userDetailsService() {
        return new NoUserDetailsService();  // avoid the default user.
    }

}
