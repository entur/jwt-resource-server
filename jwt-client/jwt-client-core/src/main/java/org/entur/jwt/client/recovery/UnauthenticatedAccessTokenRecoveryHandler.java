package org.entur.jwt.client.recovery;

import org.entur.jwt.client.AccessTokenProvider;

public interface UnauthenticatedAccessTokenRecoveryHandler {

    void handle(AccessTokenProvider accessTokenProvider, String authorizationHeader,  long currentTime);

}
