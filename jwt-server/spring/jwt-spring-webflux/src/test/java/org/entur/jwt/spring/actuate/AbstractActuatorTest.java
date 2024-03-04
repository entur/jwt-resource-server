package org.entur.jwt.spring.actuate;

import org.springframework.beans.factory.annotation.Autowired;

public class AbstractActuatorTest {

    @Autowired
    private ListJwksHealthIndicator healthIndicator;

    public void waitForHealth() throws Exception {
        // make sure health is ready before visiting
        healthIndicator.getHealth(false);

        long deadline = System.currentTimeMillis() + 1000;
        while (System.currentTimeMillis() < deadline && !healthIndicator.isIdle()) {
            Thread.sleep(10);
        }
    }
}
