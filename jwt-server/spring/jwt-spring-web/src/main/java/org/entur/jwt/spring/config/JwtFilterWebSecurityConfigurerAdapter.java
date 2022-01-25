package org.entur.jwt.spring.config;

import org.entur.jwt.spring.filter.JwtAuthenticationFilter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import static org.springframework.security.config.http.SessionCreationPolicy.STATELESS;

/**
 * Default authentication config. Extracted into its own class to allow for customization / override.
 */
public abstract class JwtFilterWebSecurityConfigurerAdapter extends WebSecurityConfigurerAdapter {

    private static Logger log = LoggerFactory.getLogger(JwtFilterWebSecurityConfigurerAdapter.class);

    protected static class NoUserDetailsService implements UserDetailsService {
        @Override
        public UserDetails loadUserByUsername(String username) {
            throw new UsernameNotFoundException("");
        }
    }

    protected final JwtAuthenticationFilter<?> filter;

    @Autowired
    public JwtFilterWebSecurityConfigurerAdapter(JwtAuthenticationFilter<?> filter) {
        this.filter = filter;
    }

    @Bean
    @Override
    public UserDetailsService userDetailsService() {
        // avoid the default user.
        return new NoUserDetailsService();
    }

    @Override
    public void configure(HttpSecurity http) throws Exception {
        // implementation note: this filter runs before the dispatcher servlet, and so
        // is out of reach of any ControllerAdvice
        log.info("Configure JWT filter");
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
    }
}

