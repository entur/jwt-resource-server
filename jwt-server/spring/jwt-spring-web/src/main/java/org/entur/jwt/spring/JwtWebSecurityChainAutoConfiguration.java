package org.entur.jwt.spring;

import org.entur.jwt.spring.auth0.properties.Auth0Flavour;
import org.entur.jwt.spring.auth0.properties.AuthorizationProperties;
import org.entur.jwt.spring.auth0.properties.Flavours;
import org.entur.jwt.spring.auth0.properties.JwtProperties;
import org.entur.jwt.spring.auth0.properties.KeycloakFlavour;
import org.entur.jwt.spring.auth0.properties.MdcProperties;
import org.entur.jwt.spring.auth0.properties.SecurityProperties;
import org.entur.jwt.spring.config.EnturAuthorizeHttpRequestsCustomizer;
import org.entur.jwt.spring.config.EnturOauth2ResourceServerCustomizer;
import org.entur.jwt.spring.config.JwtMappedDiagnosticContextFilter;
import org.entur.jwt.spring.filter.log.JwtMappedDiagnosticContextMapper;
import org.entur.jwt.spring.filter.log.JwtMappedDiagnosticContextMapperFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.BeanIds;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.security.web.header.writers.XXssProtectionHeaderWriter;

import java.util.ArrayList;
import java.util.List;

import static org.springframework.security.config.http.SessionCreationPolicy.STATELESS;

@Configuration
@ConditionalOnExpression("${entur.authorization.enabled:true} || ${entur.jwt.enabled:true}")
@EnableConfigurationProperties({SecurityProperties.class})
@AutoConfigureAfter(JwtWebAutoConfiguration.class)
public class JwtWebSecurityChainAutoConfiguration {

    private static Logger log = LoggerFactory.getLogger(JwtWebSecurityChainAutoConfiguration.class);

    @Configuration
    @ConditionalOnBean(name = BeanIds.SPRING_SECURITY_FILTER_CHAIN)
    @ConditionalOnProperty(name = {"entur.authorization.enabled"}, havingValue = "true", matchIfMissing = true)
    public static class AuthorizationConfigurationGuard {

        public AuthorizationConfigurationGuard() {
            throw new IllegalStateException("Authorization does not work for custom spring filter chain. Add 'entur.authorization.enabled=false' or disable this starter using @SpringBootApplication(exclude = {JwtWebSecurityConfigurerAdapterAutoConfiguration.class}).");
        }
    }

    @Configuration
    @ConditionalOnBean(name = BeanIds.SPRING_SECURITY_FILTER_CHAIN)
    @ConditionalOnProperty(name = {"entur.jwt.enabled"}, havingValue = "true", matchIfMissing = true)
    public static class JwtConfigurationGuard {

        public JwtConfigurationGuard() {
            throw new IllegalStateException("JWT authentication does not work for custom spring filter chain. Add 'entur.jwt.enabled=false' or disable this starter using @SpringBootApplication(exclude = {JwtWebSecurityConfigurerAdapterAutoConfiguration.class}).");
        }
    }

    @Bean
    @ConditionalOnProperty(name = {"entur.jwt.enabled"}, havingValue = "true", matchIfMissing = true)
    @ConditionalOnMissingBean(JwtAuthorityEnricher.class)
    public JwtAuthorityEnricher jwtAuthorityEnricher() {
        return new DefaultJwtAuthorityEnricher();
    }
    
    @Bean
    @ConditionalOnProperty(name = {"entur.jwt.enabled"}, havingValue = "true", matchIfMissing = false)
    @ConditionalOnMissingBean(UserDetailsService.class)
    public UserDetailsService userDetailsService() {
        return new NoUserDetailsService();  // avoid the default user.
    }

    @Configuration
    @ConditionalOnMissingBean(name = BeanIds.SPRING_SECURITY_FILTER_CHAIN)
    @ConditionalOnExpression("${entur.authorization.enabled:true} || ${entur.jwt.enabled:true}")
    @EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true)
    public static class CompositeWebSecurityConfigurerAdapter {

        private SecurityProperties securityProperties;

        public CompositeWebSecurityConfigurerAdapter(SecurityProperties securityProperties) {
            this.securityProperties = securityProperties;
        }

        @Bean
        @ConditionalOnExpression("${entur.authorization.enabled:true} && !${entur.jwt.enabled:true}")
        public SecurityFilterChain securityWebFilterChain(
                HttpSecurity http
        ) throws Exception {
            log.info("Configure without JWT");

            AuthorizationProperties authorization = securityProperties.getAuthorization();
            if (authorization.isEnabled()) {
                http.authorizeHttpRequests(new EnturAuthorizeHttpRequestsCustomizer(authorization));
            }

            return getSecurityFilterChain(http);
        }

        @Bean
        @ConditionalOnExpression("${entur.jwt.enabled:true}")
        public SecurityFilterChain filterChain(
                HttpSecurity http,
                JwkSourceMap jwkSourceMap,
                List<JwtAuthorityEnricher> jwtAuthorityEnrichers,
                List<OAuth2TokenValidator<Jwt>> jwtValidators
        ) throws Exception {

            AuthorizationProperties authorization = securityProperties.getAuthorization();
            if (authorization.isEnabled()) {
                http.authorizeHttpRequests(new EnturAuthorizeHttpRequestsCustomizer(authorization));
            }

            JwtProperties jwt = securityProperties.getJwt();
            if (jwt.isEnabled()) {

                Flavours flavours = jwt.getFlavours();
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

                http.oauth2ResourceServer(new EnturOauth2ResourceServerCustomizer(jwkSourceMap.getJwkSources(), jwtAuthorityEnrichers, jwtValidators));
            }

            MdcProperties mdc = jwt.getMdc();
            if (mdc.isEnabled()) {
                JwtMappedDiagnosticContextMapperFactory factory = new JwtMappedDiagnosticContextMapperFactory();
                JwtMappedDiagnosticContextMapper mapper = factory.mapper(mdc);
                JwtMappedDiagnosticContextFilter filter = new JwtMappedDiagnosticContextFilter(mapper);

                http.addFilterBefore(filter, AuthorizationFilter.class);
            }

            return getSecurityFilterChain(http);
        }

        private static DefaultSecurityFilterChain getSecurityFilterChain(HttpSecurity http) throws Exception {
            // https://www.baeldung.com/spring-prevent-xss
            http.headers()
                    .xssProtection().headerValue(XXssProtectionHeaderWriter.HeaderValue.ENABLED_MODE_BLOCK)
                    .and()
                    .contentSecurityPolicy("script-src 'self'");

            return http
                    .sessionManagement().sessionCreationPolicy(STATELESS).and()
                    .csrf().disable()
                    .formLogin().disable()
                    .httpBasic().disable()
                    .logout().disable()
                    .cors(Customizer.withDefaults())
                    .build();
        }

    }


}
