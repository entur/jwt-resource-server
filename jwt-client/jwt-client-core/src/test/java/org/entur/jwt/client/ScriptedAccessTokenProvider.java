package org.entur.jwt.client;

import java.util.concurrent.atomic.AtomicInteger;

/**
 * Test provider returning (or throwing) the scripted outcomes in order, repeating the last one when exhausted.
 */

public class ScriptedAccessTokenProvider implements AccessTokenProvider {

    public static AccessToken tokenExpiringIn(long millis) {
        return new AccessToken("a.b.c", "bearer", System.currentTimeMillis() + millis);
    }

    public static AccessTokenException failure() {
        return new AccessTokenException();
    }

    private final Object[] outcomes;
    private final AtomicInteger calls = new AtomicInteger();
    private Runnable beforeEachCall = () -> {
    };

    /**
     * @param outcomes each either an {@linkplain AccessToken} or an {@linkplain AccessTokenException}
     */

    public ScriptedAccessTokenProvider(Object... outcomes) {
        this.outcomes = outcomes;
    }

    public ScriptedAccessTokenProvider beforeEachCall(Runnable runnable) {
        this.beforeEachCall = runnable;
        return this;
    }

    public int getCalls() {
        return calls.get();
    }

    @Override
    public AccessToken getAccessToken(boolean forceRefresh) throws AccessTokenException {
        beforeEachCall.run();

        Object outcome = outcomes[Math.min(calls.getAndIncrement(), outcomes.length - 1)];
        if (outcome instanceof AccessTokenException e) {
            throw e;
        }
        return (AccessToken) outcome;
    }

    @Override
    public boolean supportsHealth() {
        return false;
    }

    @Override
    public void close() {
        // nothing to close
    }
}
