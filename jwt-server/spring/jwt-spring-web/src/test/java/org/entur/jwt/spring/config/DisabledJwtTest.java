package org.entur.jwt.spring.config;

import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@TestPropertySource(properties = {"entur.jwt.enabled=false"})
public class DisabledJwtTest {

    /*
    @Autowired
    private WebSecurityConfigurerAdapter adapter;

    @Test
    public void testContextLoads() {
        assertTrue(adapter instanceof AuthorizationHttpSecurityConfigurer);
    }
*/
}