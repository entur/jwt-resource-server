package org.entur.jwt.spring.config;

import org.entur.jwt.spring.JwtAutoConfiguration;
import org.entur.jwt.spring.filter.JwtServerAuthenticationConverter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.server.ServerAuthenticationEntryPoint;
import org.springframework.security.web.server.authentication.AuthenticationWebFilter;
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository;


/**
 * Default authentication config. Extracted into its own class to allow for customization / override.
 */
public abstract class JwtFilterWebSecurityConfig {

    private static Logger log = LoggerFactory.getLogger(JwtAutoConfiguration.class);

    protected static class NoUserDetailsService implements UserDetailsService {
        @Override
        public UserDetails loadUserByUsername(String username) {
            throw new UsernameNotFoundException("");
        }
    }

    protected final AuthenticationWebFilter authenticationFilter;
    protected final ServerAuthenticationEntryPoint serverAuthenticationEntryPoint;

    @Autowired
    public JwtFilterWebSecurityConfig(ReactiveAuthenticationManager manager, JwtServerAuthenticationConverter<?> converter, ServerAuthenticationEntryPoint serverAuthenticationEntryPoint) {
        this.authenticationFilter = new AuthenticationWebFilter(manager);
        this.authenticationFilter.setServerAuthenticationConverter(converter);
        this.serverAuthenticationEntryPoint = serverAuthenticationEntryPoint;
    }

    @Bean
    public ServerHttpSecurity configure(ServerHttpSecurity http) {
        log.info("Configure JWT filter");

        if (serverAuthenticationEntryPoint != null) {
            http.exceptionHandling().authenticationEntryPoint(serverAuthenticationEntryPoint);
        }

        return http
                .securityContextRepository(NoOpServerSecurityContextRepository.getInstance())
                .csrf().disable()
                .formLogin().disable()
                .httpBasic().disable()
                .logout().disable()
                .cors()
                .and()
                .addFilterAt(authenticationFilter, SecurityWebFiltersOrder.AUTHENTICATION);
    }

}
