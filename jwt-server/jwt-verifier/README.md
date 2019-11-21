
# jwt-verifier
Verification of Json Web Tokens. Wraps third party libraries for verification of signatures, parsing of tokens and so on.

Features:
 
 * wrappers for JWT verification and claim extraction
 * improved JSON Web Key (JWK) handling
   * caching with pro-active refreshes 
      * minimizes thread congestion
       * reduces spikes in processing time
       * minimizes number of calls to authorization servers
   * fault-tolerance / robustness
      * transient network error protection (retry once)
      * extended caching on outage
      * rate-limited key lookup
      * best effort key rotation support
      * health status (on last remote access)

Essentially this allows a single JWK instance to be shared within a single JVM.

## Details 
The JWK cache behaves in a __lazy, proactive__ way:

 * if empty or expired keys, the first thread to access the cache requests the keys, while all other threads must wait (are blocked, with a deadline). 
 * if the keys is about to expire, refresh them in a background thread, while returning the (still valid) current keys.

So while empty or expired keys means that the implementation is essentially blocking, this is preferable to letting all thread request the same keys from the authorization server.

Since we're refreshing the cache before the keys expire, there will normally not be both a lot of traffic and an expired cache; so thread spaghetti (by blocking) should be avoided.
 
Actively refreshing the cache is possible, if desired, as the expiry time is returned in the wrapper returned by the cache.
