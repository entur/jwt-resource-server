package org.entur.jwt.client.spring;

import okhttp3.mockwebserver.MockResponse;
import org.entur.jwt.client.spring.actuate.AccessTokenProviderHealthIndicator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.Resource;
import org.springframework.util.FileCopyUtils;

import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.io.UncheckedIOException;

import static java.nio.charset.StandardCharsets.UTF_8;

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

    public static MockResponse mockResponse(Resource resource) {
        MockResponse mockResponse = new MockResponse();
        mockResponse.setBody(asString(resource));
        mockResponse.setHeader("Content-Type", "application/json");

        return mockResponse;
    }

    public static String asString(Resource resource) {
        try (Reader reader = new InputStreamReader(resource.getInputStream(), UTF_8)) {
            return FileCopyUtils.copyToString(reader);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
