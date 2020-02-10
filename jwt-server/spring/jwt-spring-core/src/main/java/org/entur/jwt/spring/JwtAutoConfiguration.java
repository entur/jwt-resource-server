package org.entur.jwt.spring;

import static org.springframework.security.config.http.SessionCreationPolicy.STATELESS;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import org.entur.jwt.spring.actuate.JwksHealthIndicator;
import org.entur.jwt.spring.filter.JwtAuthenticationExceptionAdvice;
import org.entur.jwt.spring.filter.JwtAuthenticationFilter;
import org.entur.jwt.spring.filter.JwtAuthorityMapper;
import org.entur.jwt.spring.filter.log.DefaultJwtMappedDiagnosticContextMapper;
import org.entur.jwt.spring.filter.log.JwtMappedDiagnosticContextMapper;
import org.entur.jwt.spring.filter.resolver.JwtArgumentResolver;
import org.entur.jwt.spring.properties.AuthorizationProperties;
import org.entur.jwt.spring.properties.CorsProperties;
import org.entur.jwt.spring.properties.HttpMethodMatcher;
import org.entur.jwt.spring.properties.JwtProperties;
import org.entur.jwt.spring.properties.MatcherConfiguration;
import org.entur.jwt.spring.properties.MdcPair;
import org.entur.jwt.spring.properties.MdcProperties;
import org.entur.jwt.spring.properties.PermitAll;
import org.entur.jwt.spring.properties.SecurityProperties;
import org.entur.jwt.verifier.JwtClaimExtractor;
import org.entur.jwt.verifier.JwtVerifier;
import org.entur.jwt.verifier.JwtVerifierFactory;
import org.entur.jwt.verifier.config.JwtTenantProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.config.BeanIds;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.servlet.HandlerExceptionResolver;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
@ConditionalOnClass(WebSecurityConfigurerAdapter.class)
@EnableConfigurationProperties({ SecurityProperties.class })
@ConditionalOnProperty(name = { "entur.jwt.enabled" }, havingValue = "true", matchIfMissing = false)
public class JwtAutoConfiguration {

    private static Logger log = LoggerFactory.getLogger(JwtAutoConfiguration.class);

    private static class NoUserDetailsService implements UserDetailsService {
        @Override
        public UserDetails loadUserByUsername(String username) {
            throw new UsernameNotFoundException("");
        }
    }

    @Configuration
    @ConditionalOnMissingBean(name = BeanIds.SPRING_SECURITY_FILTER_CHAIN)
    @EnableGlobalMethodSecurity(prePostEnabled = true)
    public static class DefaultEnturWebSecurityConfig extends WebSecurityConfigurerAdapter implements WebMvcConfigurer {

        private final JwtAuthenticationFilter<?> filter;
        private final JwtArgumentResolver resolver;
        private final SecurityProperties properties;

        @Autowired
        public DefaultEnturWebSecurityConfig(JwtAuthenticationFilter<?> filter, JwtArgumentResolver resolver, SecurityProperties properties) {
            this.filter = filter;
            this.resolver = resolver;
            this.properties = properties;
        }

        @Bean
        @Override
        public UserDetailsService userDetailsService() {
            // avoid the default user.
            return new NoUserDetailsService();
        }

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            // implementation note: this filter runs before the dispatcher servlet, and so
            // is out of reach of any ControllerAdvice
            http.sessionManagement()
                    .sessionCreationPolicy(STATELESS)
                .and()
                    .csrf().disable()
                    .formLogin().disable()
                    .httpBasic().disable()
                    .logout().disable()
                    .cors()
                .and()
                    .addFilterBefore(filter, UsernamePasswordAuthenticationFilter.class);
            
            AuthorizationProperties authorizationProperties = properties.getAuthorization();
            if(authorizationProperties.isEnabled()) {
                PermitAll permitAll = authorizationProperties.getPermitAll();
                if(permitAll.isActive()) {
                    configurePermitAll(http, permitAll);
                }
                http.authorizeRequests().anyRequest().fullyAuthenticated();
            }
        }

        protected void configurePermitAll(HttpSecurity http, PermitAll permitAll) throws Exception {
            
            MatcherConfiguration mvcMatchers = permitAll.getMvcMatcher();
            if(mvcMatchers.isActive()) {
                
                if(mvcMatchers.hasPatterns()) {
                    // for all methods
                    http.authorizeRequests().mvcMatchers(mvcMatchers.getPatternsAsArray()).permitAll();
                }
                
                // for specific methods
                for (HttpMethodMatcher httpMethodMatcher : mvcMatchers.getMethod().getActiveMethods()) {
        			// check that active, empty patterns will be interpreted as permit all of the method type (empty patterns vs varargs)
        			if(httpMethodMatcher.isActive()) {
        				http.authorizeRequests().mvcMatchers(httpMethodMatcher.getVerb(), httpMethodMatcher.getPatternsAsArray()).permitAll();
        			}
                }
            }

            MatcherConfiguration antMatchers = permitAll.getAntMatcher();
            if(antMatchers.isActive()) {
                if(antMatchers.hasPatterns()) {
                    // for all methods
                    http.authorizeRequests().antMatchers(antMatchers.getPatternsAsArray()).permitAll();
                }
                
                // for specific methods
                for (HttpMethodMatcher httpMethodMatcher : antMatchers.getMethod().getActiveMethods()) {
        			// check that active, empty patterns will be interpreted as permit all of the method type (empty patterns vs varargs)
        			if(httpMethodMatcher.isActive()) {
        				http.authorizeRequests().antMatchers(httpMethodMatcher.getVerb(), httpMethodMatcher.getPatternsAsArray()).permitAll();
        			}
                }
            }
        }

        @Override
        public void addArgumentResolvers(List<HandlerMethodArgumentResolver> resolvers) {
            resolvers.add(resolver);
        }
    }

    
    
    @Configuration
    @ConditionalOnBean(name = BeanIds.SPRING_SECURITY_FILTER_CHAIN)
    public static class DefaultEnturWebMvcConfigurer implements WebMvcConfigurer {

        private final JwtArgumentResolver resolver;

        @Autowired
        public DefaultEnturWebMvcConfigurer(JwtArgumentResolver resolver) {
            this.resolver = resolver;
        }

        @Override
        public void addArgumentResolvers(List<HandlerMethodArgumentResolver> resolvers) {
            resolvers.add(resolver);
        }
    }

    @Bean
    @ConditionalOnMissingBean(JwtMappedDiagnosticContextMapper.class)
    @ConditionalOnProperty(name = { "entur.jwt.mdc.enabled" }, havingValue = "true", matchIfMissing = false)
    public <T> JwtMappedDiagnosticContextMapper<T> mapper(SecurityProperties properties, JwtClaimExtractor<T> extractor) {
        MdcProperties mdc = properties.getJwt().getMdc();
        List<MdcPair> items = mdc.getMappings();
        List<String> to = new ArrayList<>();
        List<String> from = new ArrayList<>();

        // note: possible to map the same claim to different values
        for (int i = 0; i < items.size(); i++) {
            MdcPair item = items.get(i);
            to.add(item.getTo());
            from.add(item.getFrom());

            log.info("Map JWT claim '{}' to MDC key '{}'", item.getFrom(), item.getTo());
        }
        return new DefaultJwtMappedDiagnosticContextMapper<>(from, to, extractor);
    }

    @Bean
    @ConditionalOnMissingBean(JwtVerifier.class)
    public <T> JwtVerifier<T> verifier(SecurityProperties properties, JwtVerifierFactory<T> factory) {
        Map<String, JwtTenantProperties> tenants = new HashMap<>();

        JwtProperties jwtProperties = properties.getJwt();

        List<String> filter = jwtProperties.getFilter();
        if (filter != null) {
            if (filter.isEmpty()) {
                throw new IllegalStateException("Tenant filter is empty");
            }
            // filter on name
            for (Entry<String, JwtTenantProperties> entry : jwtProperties.getTenants().entrySet()) {
                String id = entry.getKey();
                if (id != null && filter.contains(id) && entry.getValue().isEnabled()) {
                    tenants.put(id, entry.getValue());
                }
            }
        } else {
            tenants.putAll(jwtProperties.getTenants());
        }
        if (tenants.isEmpty()) {
            if (filter != null) {
                throw new IllegalStateException("No configured tenants for filter '" + filter + "'");
            } else {
                throw new IllegalStateException("No configured tenants");
            }
        }

        return factory.getVerifier(tenants, jwtProperties.getJwk(), jwtProperties.getClaims());
    }

    @Bean
    @ConditionalOnMissingBean(JwtAuthenticationFilter.class)
    public <T> JwtAuthenticationFilter<T> auth(SecurityProperties properties, JwtVerifier<T> verifier, @Autowired(required = false) JwtMappedDiagnosticContextMapper<T> mdcMapper, JwtAuthorityMapper<T> authorityMapper,
            JwtClaimExtractor<T> extractor, @Lazy HandlerExceptionResolver handlerExceptionResolver) {
        AuthorizationProperties authorizationProperties = properties.getAuthorization();

        PermitAll permitAll = authorizationProperties.getPermitAll();

        // add an extra layer of checks if auth is always required
        boolean tokenMustBePresent = authorizationProperties.isEnabled() && !permitAll.isActive();
        if (tokenMustBePresent) {
            log.info("Authentication with Json Web Token is required");
        } else {
            log.info("Authentication with Json Web Token is optional");
        }
        return new JwtAuthenticationFilter<>(verifier, tokenMustBePresent, authorityMapper, mdcMapper, extractor, handlerExceptionResolver);
    }

    @Bean("corsConfigurationSource")
    @ConditionalOnProperty(name = { "entur.cors.enabled" }, havingValue = "true", matchIfMissing = false)
    public CorsConfigurationSource corsConfigurationSource(SecurityProperties oidcAuthProperties) {

        CorsProperties cors = oidcAuthProperties.getCors();
        if (cors.getMode().equals("api")) {
            List<String> hosts = cors.getHosts();
            log.info("Enable CORS request with hosts {} for API mode", hosts);
            return getCorsConfiguration(hosts);
        } else {
            if (!cors.getHosts().isEmpty()) {
                throw new IllegalStateException("Expected empty hosts configuration for CORS mode '" + cors.getMode() + "'");
            }
            log.info("Disable CORS requests for webapp mode");

            UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();

            CorsConfiguration config = new CorsConfiguration();
            config.setAllowedOrigins(Collections.emptyList());
            config.setAllowedHeaders(Collections.emptyList());
            config.setAllowedMethods(Collections.emptyList());

            source.registerCorsConfiguration("/**", config);

            return source;
        }
    }

    @Bean("corsConfigurationSource")
    @ConditionalOnProperty(name = { "entur.security.cors.mode" }, havingValue = "webapp", matchIfMissing = false)
    public CorsConfigurationSource corsConfigurationSourceForWebapp(SecurityProperties properties) {
        log.info("Disable CORS requests for webapp mode");
        return getCorsConfiguration(Collections.emptyList());
    }

    public static CorsConfigurationSource getCorsConfiguration(List<String> hosts) {

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();

        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOrigins(hosts);
        config.setAllowedHeaders(Arrays.asList("*"));
        config.setAllowedMethods(Arrays.asList("GET", "HEAD", "POST", "PUT", "DELETE", "PATCH", "OPTIONS" // XXX
        ));
        config.setMaxAge(86400L);
        config.setAllowCredentials(true);
        source.registerCorsConfiguration("/**", config);

        return source;
    }

    @Bean
    @ConditionalOnProperty(name = { "entur.jwt.jwk.health-indicator.enabled" }, havingValue = "true", matchIfMissing = true)
    @ConditionalOnBean(JwtVerifier.class)
    public <T> JwksHealthIndicator jwksProviderHealthIndicator(JwtVerifier<T> verifier) {
        return new JwksHealthIndicator(verifier);
    }

    @Bean
    @ConditionalOnMissingBean(JwtAuthenticationExceptionAdvice.class) // allow for customization
    public JwtAuthenticationExceptionAdvice advice() {
        return new JwtAuthenticationExceptionAdvice();
    }

}
