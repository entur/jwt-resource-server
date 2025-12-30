package org.entur.jwt.client.spring.resttemplate;

import org.entur.jwt.client.spring.actuate.AccessTokenProviderHealthIndicator;
import org.springframework.beans.factory.annotation.Autowired;

public abstract class AbstractActuatorTest {

    @Autowired
    private AccessTokenProviderHealthIndicator healthIndicator;

    public void waitForHealth() throws Exception {
        // make sure health is ready before visiting
        long deadline = System.currentTimeMillis() + 10000;
        while (System.currentTimeMillis() < deadline && !healthIndicator.isIdle()) {
            Thread.sleep(100);

            System.out.println("Sleep");
        }
    }
}
