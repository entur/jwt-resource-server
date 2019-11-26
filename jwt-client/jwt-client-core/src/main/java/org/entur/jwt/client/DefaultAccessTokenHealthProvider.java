package org.entur.jwt.client;

import java.io.IOException;

public class DefaultAccessTokenHealthProvider extends BaseAccessTokenProvider {

	private volatile AccessTokenHealth status;

	/** 
	 * Provider to invoke when refreshing state. This should be the top level provider,
	 * so that caches are actually populated and so on. 
	 */

	private AccessTokenProvider refreshProvider;

	public DefaultAccessTokenHealthProvider(AccessTokenProvider provider) {
		super(provider);
	}

	@Override
	public AccessToken getAccessToken(boolean forceRefresh) throws AccessTokenException {
		long time = System.currentTimeMillis();

		AccessToken accessToken = null;
		try {
			accessToken = provider.getAccessToken(forceRefresh);
		} finally {
			this.status = new AccessTokenHealth(time, accessToken != null);
		}

		return accessToken;
	}

	@Override
	public void close() throws IOException {
		provider.close();
	}

	@Override
	public AccessTokenHealth getHealth(boolean refresh) {
		AccessTokenHealth threadSafeStatus = this.status; // defensive copy
		if(refresh &&  (threadSafeStatus == null || !threadSafeStatus.isSuccess())) { 
			// get a fresh status
			try {
				refreshProvider.getAccessToken(false);
			} catch(Exception e) {
				// ignore
				logger.warn("Exception refreshing health status.", e);
			} finally {
				// so was this provider actually invoked?
				// check whether we got a new status
				if(this.status != threadSafeStatus) {
					threadSafeStatus = this.status;
				} else {
					// assume a provider above this instance
					// was able to compensate somehow
					threadSafeStatus = new AccessTokenHealth(System.currentTimeMillis(), true);
				}
			}
		}
		return threadSafeStatus;
	}

	public void setRefreshProvider(AccessTokenProvider top) {
		this.refreshProvider = top;
	}
}
