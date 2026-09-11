package org.entur.jwt.spring.perf;

/**
 * Shared timing helper for the HTTP back-to-back-request benchmarks in this package.
 */
final class HttpBenchmarkSupport {

    interface HttpCall {
        void request(int i);
    }

    record Stats(String label, double avgLatencyMicros, double opsPerSecond) {
    }

    private HttpBenchmarkSupport() {
    }

    /**
     * Issues {@code requests} real HTTP requests back to back (after a warm-up phase of
     * {@code warmup} requests, to let the JIT and connection pool settle), then reports
     * average per-request latency and throughput.
     */
    static Stats measure(String label, int requests, int warmup, HttpCall call) {
        for (int i = 0; i < warmup; i++) {
            call.request(i);
        }

        long start = System.nanoTime();
        for (int i = 0; i < requests; i++) {
            call.request(i);
        }
        long durationNanos = System.nanoTime() - start;

        double avgLatencyMicros = (durationNanos / 1000.0) / requests;
        double opsPerSecond = requests / (durationNanos / 1_000_000_000.0);

        System.out.printf("[%s] %.1f us/request, %.0f requests/sec (%d requests back to back)%n",
                label, avgLatencyMicros, opsPerSecond, requests);

        return new Stats(label, avgLatencyMicros, opsPerSecond);
    }
}
