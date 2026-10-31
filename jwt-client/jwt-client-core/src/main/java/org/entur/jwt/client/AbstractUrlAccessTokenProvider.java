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
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;
import java.util.stream.Collectors;

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

    /** Default delay after a failure without a usable Retry-After header, in milliseconds. */
    public static final long DEFAULT_RETRY_AFTER_FALLBACK_MILLIS = 15_000;

    private static final String RETRY_AFTER_HEADER = "Retry-After";
    // Auth0 and Okta respectively; both are UNIX timestamps in seconds
    private static final String RATE_LIMIT_RESET_HEADER = "X-RateLimit-Reset";
    private static final String RATE_LIMIT_RESET_HEADER_HYPHENATED = "X-Rate-Limit-Reset";
    private static final List<String> CONTEXT_HEADERS = List.of(RETRY_AFTER_HEADER,
            "X-RateLimit-Limit", "X-RateLimit-Remaining", RATE_LIMIT_RESET_HEADER,
            "X-Rate-Limit-Limit", "X-Rate-Limit-Remaining", RATE_LIMIT_RESET_HEADER_HYPHENATED,
            "Auth0-Client-Quota-Limit", "Auth0-Organization-Quota-Limit");

    private volatile long retryAfterFallbackMillis = DEFAULT_RETRY_AFTER_FALLBACK_MILLIS;
    private volatile Long retryAfterDeadlineNanos;

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
     * Refuse to send a token request while the retry deadline is active.
     *
     * @param cause failure which led to this request, or null
     * @throws AccessTokenRetryAfterException if the deadline has not yet elapsed
     */
    protected void checkRetryDeadline(Throwable cause) throws AccessTokenRetryAfterException {
        Long deadline = getRetryAfterDeadlineNanos();
        if (deadline != null && deadline - nanoTime() > 0) {
            throw new AccessTokenRetryAfterException("Token request deferred until the retry deadline", cause, deadline);
        }
    }

    /**
     * Start the fallback backoff for a failed token request, unless the failure already carries a deadline.
     *
     * @param failure the failed request
     * @return the exception to throw; unavailable failures carry the deadline, others keep their type
     */
    protected AccessTokenException recordFailure(AccessTokenException failure) {
        long fallbackMillis = retryAfterFallbackMillis;
        if (failure instanceof AccessTokenRetryAfterException || fallbackMillis == 0) {
            return failure;
        }
        long deadline = deferTokenRequests(TimeUnit.MILLISECONDS.toNanos(fallbackMillis));
        if (failure instanceof AccessTokenUnavailableException) {
            return new AccessTokenRetryAfterException(failure.getMessage(), failure, deadline);
        }
        return failure;
    }

    /**
     * Record a failed HTTP response's retry deadline, or the configured fallback.
     *
     * @param message failure description
     * @param headers response header lookup by name, or null when no headers are available
     * @return unavailable exception carrying the fixed deadline, or an ordinary one when no deadline can be derived and the fallback is zero
     * @see #retryAfterException(String, Function, Throwable)
     */
    protected AccessTokenUnavailableException retryAfterException(String message, Function<String, String> headers) {
        return retryAfterException(message, headers, null);
    }

    /**
     * Record a failed HTTP response's retry deadline and retain its cause.
     * <p>
     * The delay is taken from Retry-After, otherwise from the X-RateLimit-Reset or X-Rate-Limit-Reset
     * UNIX timestamp, otherwise from the configured fallback. A reset timestamp which is not in the future is ignored.
     * The rate limit headers which are present are kept as context on the exception, and appended to its message.
     *
     * @param message failure description
     * @param headers response header lookup by name, or null when no headers are available
     * @param cause original HTTP failure, or null
     * @return unavailable exception with a deadline, or an ordinary one when no deadline can be derived and the fallback is zero
     */
    protected AccessTokenUnavailableException retryAfterException(String message, Function<String, String> headers, Throwable cause) {
        Map<String, String> context = rateLimitHeaders(headers);
        if (!context.isEmpty()) {
            message = message + " " + context.entrySet().stream().map(e -> e.getKey() + ":" + e.getValue()).collect(Collectors.joining(", "));
        }
        Long delay = parseRetryAfterNanos(context.get(RETRY_AFTER_HEADER));
        if (delay == null) {
            delay = parseResetNanos(context.get(RATE_LIMIT_RESET_HEADER));
        }
        if (delay == null) {
            delay = parseResetNanos(context.get(RATE_LIMIT_RESET_HEADER_HYPHENATED));
        }
        if (delay == null) {
            long fallbackMillis = retryAfterFallbackMillis;
            if (fallbackMillis == 0) {
                return new AccessTokenUnavailableException(message, cause);
            }
            delay = TimeUnit.MILLISECONDS.toNanos(fallbackMillis);
        }
        return new AccessTokenRetryAfterException(message, cause, deferTokenRequests(delay), context);
    }

    private static Map<String, String> rateLimitHeaders(Function<String, String> headers) {
        Map<String, String> context = new LinkedHashMap<>();
        if (headers != null) {
            for (String name : CONTEXT_HEADERS) {
                String value = headers.apply(name);
                if (value != null) {
                    context.put(name, value);
                }
            }
        }
        return context;
    }

    private Long parseResetNanos(String header) {
        if (header == null || header.isBlank()) {
            return null;
        }
        try {
            long millis = Math.subtractExact(Math.multiplyExact(Long.parseLong(header.trim()), 1000L), currentTimeMillis());
            return millis > 0 ? TimeUnit.MILLISECONDS.toNanos(millis) : null;
        } catch (NumberFormatException | ArithmeticException e) {
            LOGGER.warn("Invalid rate limit reset header ignored");
            return null;
        }
    }

    private Long parseRetryAfterNanos(String header) {
        if (header == null || header.isBlank()) {
            return null;
        }
        String value = header.trim();
        try {
            if (value.matches("[0-9]+")) {
                try {
                    return TimeUnit.SECONDS.toNanos(Long.parseLong(value));
                } catch (NumberFormatException e) {
                    LOGGER.warn("Retry-After delay exceeds the supported range; using the maximum backoff");
                    return Long.MAX_VALUE;
                }
            }
            long millis = Math.subtractExact(ZonedDateTime.parse(value, DateTimeFormatter.RFC_1123_DATE_TIME)
                    .toInstant().toEpochMilli(), currentTimeMillis());
            return TimeUnit.MILLISECONDS.toNanos(Math.max(0L, millis));
        } catch (DateTimeException | ArithmeticException e) {
            LOGGER.warn("Invalid Retry-After header ignored");
            return null;
        }
    }

    // not synchronized: token requests are serialized by ExclusiveAccessTokenProvider
    private long deferTokenRequests(long delayNanos) {
        long now = nanoTime();
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
        return retryAfterDeadlineNanos;
    }

    /**
     * Configure the fallback used when a failed request has no usable server delay.
     *
     * @param millis fallback after failure without a usable header; zero leaves such failures ordinary, so no deadline is recorded and the retry wrapper may retry once
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

        checkRetryDeadline(null);

        ClientCredentialsResponse token;
        try {
            token = getToken();
        } catch (AccessTokenException e) {
            throw recordFailure(e);
        }

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
