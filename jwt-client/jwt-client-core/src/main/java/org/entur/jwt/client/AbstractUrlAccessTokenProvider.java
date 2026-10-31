package org.entur.jwt.client;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.DateTimeException;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Map;
import java.util.Map.Entry;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Abstract provider using URL. This simple abstraction exists so that the
 * underlying HTTP client can be swapped.
 *
 */

public abstract class AbstractUrlAccessTokenProvider implements AccessTokenProvider {

    private static final Logger LOGGER = LoggerFactory.getLogger(AbstractUrlAccessTokenProvider.class);

    protected static final String CONTENT_TYPE = "application/x-www-form-urlencoded";
    protected static final String KEY_GRANT_TYPE = "grant_type";

    protected final URL issueUrl;
    protected final byte[] issueBody;
    protected final Map<String, Object> issueHeaders;

    private final ReentrantLock tokenRequestLock = new ReentrantLock();
    private volatile boolean retryAfterEnabled = true;
    private volatile long retryAfterFallbackMillis = 15_000;
    private volatile Long retryAfterDeadlineNanos;

    /**
     * A token request and its associated state updates, excluding revocation.
     *
     * @param <T> request result
     */
    @FunctionalInterface
    protected interface TokenRequest<T> {
        /**
         * Execute the guarded token operation.
         *
         * @return request result
         * @throws AccessTokenException if the request fails
         */
        T execute() throws AccessTokenException;
    }

    public AbstractUrlAccessTokenProvider(URL issueUrl, Map<String, Object> parameters, Map<String, Object> headers) {
        super();

        checkArgument(issueUrl != null, "A non-null url is required");
        checkArgument(parameters != null, "A non-null body parameters is required");
        checkArgument(headers != null, "A non-null headers is required");

        this.issueUrl = issueUrl;
        this.issueBody = createBody(parameters);
        this.issueHeaders = headers;
    }

    protected void checkArgument(boolean valid, String message) {
        if (!valid) {
            throw new IllegalArgumentException(message);
        }
    }

    protected byte[] createBody(Map<String, Object> map) {
        StringBuilder builder = new StringBuilder();

        if (!map.isEmpty()) {
            for (Entry<String, Object> entry : map.entrySet()) {
                builder.append(entry.getKey());
                builder.append('=');
                builder.append(encode(entry.getValue().toString()));
                builder.append('&');
            }
            builder.setLength(builder.length() - 1);
        }
        return builder.toString().getBytes(StandardCharsets.UTF_8);
    }

    protected String encode(String value) {
        try {
            return URLEncoder.encode(value, StandardCharsets.UTF_8.name());
        } catch (UnsupportedEncodingException e) {
            throw new IllegalArgumentException(e);
        }
    }

    protected abstract ClientCredentialsResponse getToken() throws AccessTokenException;

    /**
     * Execute one token request without allowing concurrent calls or calls during backoff.
     *
     * @param request issuance or refresh operation
     * @param <T> request result
     * @return token response
     * @throws AccessTokenException if the request fails or is deferred
     */
    protected <T> T requestToken(TokenRequest<T> request) throws AccessTokenException {
        if (!tokenRequestLock.tryLock()) {
            throw new AccessTokenUnavailableException("A token request is already in progress");
        }
        try {
            Long deadline = getRetryAfterDeadlineNanos();
            if (deadline != null && deadline - nanoTime() > 0) {
                throw new AccessTokenRetryAfterException("Token request deferred until the retry deadline", null, deadline);
            }
            try {
                return request.execute();
            } catch (AccessTokenException e) {
                if (retryAfterEnabled && !(e instanceof AccessTokenRetryAfterException)) {
                    long retryDeadline = deferTokenRequests(TimeUnit.MILLISECONDS.toNanos(retryAfterFallbackMillis));
                    if (e instanceof AccessTokenUnavailableException) {
                        throw new AccessTokenRetryAfterException(e.getMessage(), e, retryDeadline);
                    }
                }
                throw e;
            }
        } finally {
            tokenRequestLock.unlock();
        }
    }

    /**
     * Record a failed HTTP response's Retry-After header, or the configured fallback.
     *
     * @param message failure description
     * @param header Retry-After value, or null when absent
     * @return unavailable exception carrying the fixed deadline when backoff is enabled
     */
    protected AccessTokenUnavailableException retryAfterException(String message, String header) {
        return retryAfterException(message, header, null);
    }

    /**
     * Record a failed HTTP response's retry deadline and retain its cause.
     *
     * @param message failure description
     * @param header Retry-After value, or null when absent
     * @param cause original HTTP failure, or null
     * @return unavailable exception with retry metadata when backoff is enabled
     */
    protected AccessTokenUnavailableException retryAfterException(String message, String header, Throwable cause) {
        if (!retryAfterEnabled) {
            return new AccessTokenUnavailableException(message, cause);
        }
        long delay = TimeUnit.MILLISECONDS.toNanos(retryAfterFallbackMillis);
        if (header != null && !header.isBlank()) {
            String value = header.trim();
            try {
                if (value.matches("[0-9]+")) {
                    try {
                        delay = TimeUnit.SECONDS.toNanos(Long.parseLong(value));
                    } catch (NumberFormatException e) {
                        LOGGER.warn("Retry-After delay exceeds the supported range; using the maximum backoff");
                        delay = Long.MAX_VALUE;
                    }
                } else {
                    long millis = Math.subtractExact(ZonedDateTime.parse(value, DateTimeFormatter.RFC_1123_DATE_TIME)
                            .toInstant().toEpochMilli(), currentTimeMillis());
                    delay = TimeUnit.MILLISECONDS.toNanos(Math.max(0L, millis));
                }
            } catch (DateTimeException | ArithmeticException e) {
                LOGGER.warn("Invalid Retry-After header; using the configured fallback delay");
            }
        }
        return new AccessTokenRetryAfterException(message, cause, deferTokenRequests(delay));
    }

    private synchronized long deferTokenRequests(long delayNanos) {
        long now = nanoTime();
        if (!retryAfterEnabled) {
            return now;
        }
        Long current = retryAfterDeadlineNanos;
        if (current == null || delayNanos > current - now) {
            retryAfterDeadlineNanos = now + delayNanos;
        }
        return retryAfterDeadlineNanos;
    }

    /**
     * Read the current token-request backoff without starting a request.
     *
     * @return JVM-local deadline in the {@link System#nanoTime()} time domain, or null if none is known;
     *         the deadline may already have elapsed
     */
    public Long getRetryAfterDeadlineNanos() {
        return retryAfterEnabled ? retryAfterDeadlineNanos : null;
    }

    /**
     * Enable backoff enforcement, or disable it and clear the current deadline.
     *
     * @param enabled whether server directives and fallback backoff are enforced
     */
    public synchronized void setRetryAfterEnabled(boolean enabled) {
        retryAfterEnabled = enabled;
        if (!enabled) {
            retryAfterDeadlineNanos = null;
        }
    }

    /**
     * Configure the fallback used when a failed request has no usable server delay.
     *
     * @param millis fallback after failure without a usable header; zero disables only this fallback
     */
    public void setRetryAfterFallbackMillis(long millis) {
        checkArgument(millis >= 0, "Retry-After fallback must not be negative");
        retryAfterFallbackMillis = millis;
    }

    /**
     * Read the clock used for retry deadlines.
     * @return current monotonic time, in nanoseconds
     */
    protected long nanoTime() {
        return System.nanoTime();
    }

    /**
     * Read the clock used to interpret HTTP-dates and token lifetimes.
     * @return current wall-clock time, in milliseconds since the epoch
     */
    protected long currentTimeMillis() {
        return System.currentTimeMillis();
    }

    @Override
    public AccessToken getAccessToken(boolean forceRefresh) throws AccessTokenException {
        long time = currentTimeMillis();

        ClientCredentialsResponse token = requestToken(this::getToken);

        return new AccessToken(token.getAccessToken(), token.getTokenType(), time + token.getExpiresIn() * 1000);
    }

    @Override
    public void close() throws IOException {
        // NOOP, access-tokens are stateless
    }

    protected void validate(ClientCredentialsResponse clientCredentialsResponse) throws AccessTokenUnavailableException {
        if (clientCredentialsResponse == null) {
            throw new AccessTokenUnavailableException("Response body is empty");
        }
        if (clientCredentialsResponse.getExpiresIn() == null) {
            throw new AccessTokenUnavailableException("Expires-in is not specified");
        }
        if (clientCredentialsResponse.getTokenType() == null) {
            throw new AccessTokenUnavailableException("Token-type is not specified");
        }
        if (clientCredentialsResponse.getAccessToken() == null) {
            throw new AccessTokenUnavailableException("Access-token is not specified");
        }
    }
}
