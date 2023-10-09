package org.entur.jwt.spring.rest;

import org.entur.jwt.junit5.AuthorizationServer;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.test.context.junit.jupiter.SpringExtension;

@AuthorizationServer
@ExtendWith(SpringExtension.class)
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
