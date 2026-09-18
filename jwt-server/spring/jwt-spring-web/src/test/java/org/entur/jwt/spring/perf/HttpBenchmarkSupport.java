package org.entur.jwt.spring.perf;

import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Shared timing helper for the HTTP back-to-back-request benchmarks in this package.
 * <p>
 * All measurements here run one dedicated client thread per token (each with its own
 * {@code HttpClient}/connection), all synchronized to start at the same instant via a
 * {@link CyclicBarrier}, so the numbers reflect real concurrent client load rather than
 * a single thread round-robining across tokens.
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
     * Runs {@code calls.length} client threads in parallel (one dedicated call/client
     * per thread), each issuing {@code requestsPerClient} back-to-back requests (after
     * an independent {@code warmupPerClient}-request warm-up), all starting at the same
     * instant. Reports aggregate throughput across all client threads combined.
     */
    static Stats measureParallel(String label, int requestsPerClient, int warmupPerClient, HttpCall[] calls) {
        int clients = calls.length;
        CyclicBarrier barrier = new CyclicBarrier(clients);
        Thread[] threads = new Thread[clients];
        long[] durationsNanos = new long[clients];

        for (int c = 0; c < clients; c++) {
            int idx = c;
            threads[c] = new Thread(() -> {
                for (int i = 0; i < warmupPerClient; i++) {
                    calls[idx].request(i);
                }
                await(barrier);
                long start = System.nanoTime();
                for (int i = 0; i < requestsPerClient; i++) {
                    calls[idx].request(i);
                }
                durationsNanos[idx] = System.nanoTime() - start;
            }, "http-bench-client-" + c);
        }

        for (Thread t : threads) {
            t.start();
        }
        for (Thread t : threads) {
            join(t);
        }

        long maxDurationNanos = 0;
        for (long d : durationsNanos) {
            maxDurationNanos = Math.max(maxDurationNanos, d);
        }

        long totalRequests = (long) requestsPerClient * clients;
        double avgLatencyMicros = (maxDurationNanos / 1000.0) / requestsPerClient;
        double opsPerSecond = totalRequests / (maxDurationNanos / 1_000_000_000.0);

        System.out.printf(
                "[%s] %d parallel client(s), %.1f us/request (per client), %.0f requests/sec aggregate (%,d requests total)%n",
                label, clients, avgLatencyMicros, opsPerSecond, totalRequests);

        return new Stats(label, avgLatencyMicros, opsPerSecond);
    }

    /**
     * Runs {@code calls.length} client threads in parallel (one dedicated call/client
     * per thread), each hammering the endpoint continuously starting from a completely
     * cold state (no warm-up at all), all synchronized to start at the same instant.
     * Reports the throughput of each individual segment (since the previous checkpoint,
     * not cumulative since the start of the run), summed across all client threads, at
     * each wall-clock checkpoint in {@code checkpointSeconds} (e.g.
     * {@code {1, 2, 3, 4, 5, 10, 15}}), so the cache warm-up curve is visible within a
     * single run.
     */
    static void measureColdStartIntervalsParallel(String label, int[] checkpointSeconds, HttpCall[] calls) {
        int clients = calls.length;
        AtomicInteger[] counters = new AtomicInteger[clients];
        for (int c = 0; c < clients; c++) {
            counters[c] = new AtomicInteger();
        }
        AtomicBoolean stop = new AtomicBoolean(false);
        CyclicBarrier barrier = new CyclicBarrier(clients + 1);

        Thread[] threads = new Thread[clients];
        for (int c = 0; c < clients; c++) {
            int idx = c;
            threads[c] = new Thread(() -> {
                await(barrier);
                int i = 0;
                while (!stop.get()) {
                    calls[idx].request(i++);
                    counters[idx].incrementAndGet();
                }
            }, "http-bench-client-" + c);
            threads[c].start();
        }

        await(barrier);
        long runStart = System.nanoTime();
        long segmentStart = runStart;
        int[] callsAtSegmentStart = new int[clients];

        for (int checkpointSecond : checkpointSeconds) {
            long checkpointNanos = runStart + checkpointSecond * 1_000_000_000L;
            sleepUntil(checkpointNanos);

            long now = System.nanoTime();
            int segmentCalls = 0;
            for (int c = 0; c < clients; c++) {
                int current = counters[c].get();
                segmentCalls += current - callsAtSegmentStart[c];
                callsAtSegmentStart[c] = current;
            }

            double segmentSeconds = (now - segmentStart) / 1_000_000_000.0;
            double segmentOpsPerSecond = segmentCalls / segmentSeconds;

            System.out.printf(
                    "[%s] t=%ds: %d parallel clients, segment %,d requests in %.2fs (%.0f requests/sec)%n",
                    label, checkpointSecond, clients, segmentCalls, segmentSeconds, segmentOpsPerSecond);

            segmentStart = now;
        }

        stop.set(true);
        for (Thread t : threads) {
            join(t);
        }
    }

    private static void await(CyclicBarrier barrier) {
        try {
            barrier.await();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static void join(Thread t) {
        try {
            t.join();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(e);
        }
    }

    private static void sleepUntil(long targetNanoTime) {
        long remaining = targetNanoTime - System.nanoTime();
        if (remaining <= 0) {
            return;
        }
        try {
            TimeUnit.NANOSECONDS.sleep(remaining);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(e);
        }
    }
}
