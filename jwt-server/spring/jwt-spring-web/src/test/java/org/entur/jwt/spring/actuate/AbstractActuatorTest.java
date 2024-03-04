package org.entur.jwt.spring.actuate;

import org.springframework.beans.factory.annotation.Autowired;

public class AbstractActuatorTest {

    @Autowired
    private ListJwksHealthIndicator healthIndicator;

    public void waitForHealth() throws Exception {
        long deadline = System.currentTimeMillis() + 10000;
        while (System.currentTimeMillis() < deadline && !healthIndicator.isIdle()) {
            Thread.sleep(100);

            System.out.println("Sleep");
        }
    }
}
