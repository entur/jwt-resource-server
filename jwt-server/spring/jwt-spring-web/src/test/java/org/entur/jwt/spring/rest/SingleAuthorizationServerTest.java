package org.entur.jwt.spring.rest;

import org.entur.jwt.junit5.AuthorizationServer;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;

@AuthorizationServer
@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
public class SingleAuthorizationServerTest {

    /*
    @Autowired
    private JwtVerifier<?> verifier;

    @Test
    public void test(@MyAccessToken(myId = 1) String token) throws Exception {
        verifier.verify(token);
    }

     */
}
