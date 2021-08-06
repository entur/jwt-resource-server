package org.entur.jwt.client.springreactive;

import org.entur.jwt.client.AccessTokenProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationListener;
import org.springframework.context.event.ContextStartedEvent;

import java.util.Map;
import java.util.Map.Entry;

/**
 *
 * This kicks off the eager JWT caching, if enabled. If fetching JWTs fail, a warning is logged.
 *
 */

public class EagerContextStartedListener implements ApplicationListener<ContextStartedEvent> {

	// implementation note: perhaps it would be better to use ContextRefreshedEvent,
	// triggering this behavior requires an implicit call to applicationContext.start(),
	// however this would always fail on unit tests, when mocking is inserted after application
	// context is loaded (refreshed).

    private static Logger log = LoggerFactory.getLogger(EagerContextStartedListener.class);

	private final Map<String, AccessTokenProvider> providersById;

	public EagerContextStartedListener(Map<String, AccessTokenProvider> providersById) {
		this.providersById = providersById;
	}

	@Override
	public void onApplicationEvent(ContextStartedEvent cse) {
		if(!providersById.isEmpty()) {
			log.info("Eagerly refreshing {} providers", providersById.size());
			for (Entry<String, AccessTokenProvider> entry : providersById.entrySet()) {
				try {
					entry.getValue().getAccessToken(false);
				} catch (Throwable e) {
					log.warn("Unable to eagerly load JWT on context started for {}", entry.getKey());
				}
			}
		}
	}
}
