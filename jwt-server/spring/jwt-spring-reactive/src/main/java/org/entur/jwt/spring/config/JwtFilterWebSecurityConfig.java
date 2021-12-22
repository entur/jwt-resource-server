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
import org.springframework.security.core.userdetails.*;
import org.springframework.security.web.server.ServerAuthenticationEntryPoint;
import org.springframework.security.web.server.authentication.AuthenticationWebFilter;
import org.springframework.security.web.server.authentication.ServerAuthenticationFailureHandler;
import org.springframework.security.web.server.authorization.ExceptionTranslationWebFilter;
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository;
import reactor.core.publisher.Mono;


/**
 * Default authentication config. Extracted into its own class to allow for customization / override.
 */
public abstract class JwtFilterWebSecurityConfig {

    private static Logger log = LoggerFactory.getLogger(JwtAutoConfiguration.class);

    protected static class NoUserDetailsService implements ReactiveUserDetailsService {
        @Override
        public Mono<UserDetails> findByUsername(String username) {
            throw new UsernameNotFoundException("");
        }
    }

    protected final AuthenticationWebFilter authenticationFilter;
    protected final ExceptionTranslationWebFilter exceptionTranslationWebFilter;
    protected final ServerAuthenticationEntryPoint serverAuthenticationEntryPoint;

    @Autowired
    public JwtFilterWebSecurityConfig(ReactiveAuthenticationManager manager, JwtServerAuthenticationConverter<?> converter, ServerAuthenticationEntryPoint serverAuthenticationEntryPoint, ServerAuthenticationFailureHandler serverAuthenticationFailureHandler) {
        this.authenticationFilter = new AuthenticationWebFilter(manager);
        this.authenticationFilter.setServerAuthenticationConverter(converter);
        this.authenticationFilter.setAuthenticationFailureHandler(serverAuthenticationFailureHandler);

        this.exceptionTranslationWebFilter = new ExceptionTranslationWebFilter();
        this.exceptionTranslationWebFilter.setAuthenticationEntryPoint(serverAuthenticationEntryPoint);

        this.serverAuthenticationEntryPoint = serverAuthenticationEntryPoint;
    }

    @Bean
    public ReactiveUserDetailsService reactiveUserDetailsService() {
        // avoid the default user.
        return new NoUserDetailsService();
    }

    public ServerHttpSecurity configure(ServerHttpSecurity http) {
        log.info("Configure JWT filter");

        return http
                .securityContextRepository(NoOpServerSecurityContextRepository.getInstance())
                .csrf().disable()
                .formLogin().disable()
                .httpBasic().disable()
                .logout().disable()
                .cors()
                .and()
                .exceptionHandling().authenticationEntryPoint(serverAuthenticationEntryPoint)
                .and()
                .addFilterAt(authenticationFilter, SecurityWebFiltersOrder.AUTHENTICATION)
                .addFilterAt(exceptionTranslationWebFilter, SecurityWebFiltersOrder.EXCEPTION_TRANSLATION);
    }

}
