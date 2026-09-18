package org.entur.jwt.spring;

import org.junit.jupiter.api.Test;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import static org.junit.jupiter.api.Assertions.assertThrows;

class NoUserDetailsServiceTest {

    @Test
    void alwaysThrowsUsernameNotFoundException() {
        NoUserDetailsService service = new NoUserDetailsService();
        assertThrows(UsernameNotFoundException.class, () -> service.loadUserByUsername("someone"));
    }
}
