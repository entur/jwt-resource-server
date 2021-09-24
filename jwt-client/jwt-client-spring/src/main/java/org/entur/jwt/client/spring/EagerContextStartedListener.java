package org.entur.jwt.client.spring;

import org.entur.jwt.client.AccessTokenProvider;
import org.entur.jwt.client.springcore.AbstractEagerContextStartedListener;

import java.util.Map;

/**
 *
 * This kicks off the eager JWT caching, if enabled. If fetching JWTs fail, a warning is logged.
 *
 */

public class EagerContextStartedListener extends AbstractEagerContextStartedListener {

    public EagerContextStartedListener(Map<String, AccessTokenProvider> providersById) {
        super(providersById);
    }
}
