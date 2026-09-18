package org.entur.jwt.spring.grpc.perf;

/**
 * Shared timing helper for the gRPC back-to-back-request benchmarks in this package.
 * <p>
 * Mirrors {@code org.entur.jwt.spring.perf.HttpBenchmarkSupport} in jwt-spring-web, but
 * for real gRPC calls over a TCP loopback channel instead of HTTP.
 */
final class GrpcBenchmarkSupport {

    interface GrpcCall {
        void call(int i);
    }

    record Stats(String label, double avgLatencyMicros, double opsPerSecond) {
    }

    private GrpcBenchmarkSupport() {
    }

    /**
     * Issues {@code requests} real gRPC calls back to back (after a warm-up phase of
     * {@code warmup} calls, to let the JIT and connection settle), then reports average
     * per-call latency and throughput.
     */
    static Stats measure(String label, int requests, int warmup, GrpcCall call) {
        for (int i = 0; i < warmup; i++) {
            call.call(i);
        }

        long start = System.nanoTime();
        for (int i = 0; i < requests; i++) {
            call.call(i);
        }
        long durationNanos = System.nanoTime() - start;

        double avgLatencyMicros = (durationNanos / 1000.0) / requests;
        double opsPerSecond = requests / (durationNanos / 1_000_000_000.0);

        System.out.printf("[%s] %.1f us/call, %.0f calls/sec (%d calls back to back)%n",
                label, avgLatencyMicros, opsPerSecond, requests);

        return new Stats(label, avgLatencyMicros, opsPerSecond);
    }

    /**
     * Issues real gRPC calls back to back starting from a completely cold state (no
     * warm-up at all), for a single continuous run, reporting throughput at each
     * cumulative wall-clock checkpoint in {@code checkpointSeconds} (e.g.
     * {@code {1, 2, 3, 4, 5, 10, 15}}). For each checkpoint this logs both the
     * throughput of that individual segment (since the previous checkpoint) and the
     * cumulative throughput since the very first call, so the cache warm-up curve is
     * visible within a single run.
     */
    static void measureColdStartIntervals(String label, int[] checkpointSeconds, GrpcCall call) {
        long runStart = System.nanoTime();
        long segmentStart = runStart;
        int callIndex = 0;
        int callsAtSegmentStart = 0;

        for (int checkpointSecond : checkpointSeconds) {
            long checkpointNanos = runStart + checkpointSecond * 1_000_000_000L;

            while (System.nanoTime() < checkpointNanos) {
                call.call(callIndex++);
            }

            long now = System.nanoTime();

            int segmentCalls = callIndex - callsAtSegmentStart;
            double segmentSeconds = (now - segmentStart) / 1_000_000_000.0;
            double segmentOpsPerSecond = segmentCalls / segmentSeconds;

            double cumulativeSeconds = (now - runStart) / 1_000_000_000.0;
            double cumulativeOpsPerSecond = callIndex / cumulativeSeconds;

            System.out.printf(
                    "[%s] t=%ds: segment %,d calls in %.2fs (%.0f calls/sec), cumulative %,d calls in %.2fs (%.0f calls/sec)%n",
                    label, checkpointSecond, segmentCalls, segmentSeconds, segmentOpsPerSecond,
                    callIndex, cumulativeSeconds, cumulativeOpsPerSecond);

            segmentStart = now;
            callsAtSegmentStart = callIndex;
        }
    }
}
