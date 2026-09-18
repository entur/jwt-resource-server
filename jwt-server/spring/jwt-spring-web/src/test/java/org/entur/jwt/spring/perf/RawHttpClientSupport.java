package org.entur.jwt.spring.perf;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

/**
 * Minimal, low-overhead HTTP client for the benchmarks in this package.
 * <p>
 * {@code TestRestTemplate} (backed by Spring's {@code RestTemplate}) adds noticeable
 * client-side overhead of its own on top of the network round trip - interceptors,
 * message converter/Jackson resolution, error handling, root-URI resolution, etc. - which
 * would otherwise dominate the timed measurements and mask the effect of the decoded-JWT
 * cache. This uses the JDK's {@link HttpClient} directly instead, with no response body
 * deserialization in the hot path - only a cheap {@code String.contains} check to confirm
 * the call actually succeeded end to end.
 * <p>
 * Each instance owns its own {@code HttpClient} (and thus its own HTTP/1.1 keep-alive
 * connection), so that in the parallel benchmarks each client thread gets a dedicated
 * connection rather than sharing one across threads.
 */
final class RawHttpClientSupport {

    private final HttpClient client = HttpClient.newBuilder()
            .version(HttpClient.Version.HTTP_1_1)
            .build();

    void assertProtectedRequestSucceeds(int port, String token, String expectedMessage) {
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create("http://localhost:" + port + "/protected"))
                .header("Authorization", token)
                .GET()
                .build();

        HttpResponse<String> response;
        try {
            response = client.send(request, HttpResponse.BodyHandlers.ofString());
        } catch (IOException | InterruptedException e) {
            throw new IllegalStateException("Request to /protected failed", e);
        }

        if (response.statusCode() != 200) {
            throw new IllegalStateException("Expected status 200 but got " + response.statusCode());
        }
        if (!response.body().contains(expectedMessage)) {
            throw new IllegalStateException("Unexpected response body: " + response.body());
        }
    }
}
