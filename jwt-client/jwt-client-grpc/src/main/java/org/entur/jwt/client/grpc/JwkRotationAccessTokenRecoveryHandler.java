package org.entur.jwt.client.grpc;

import org.entur.jwt.client.AccessTokenProvider;

public interface JwkRotationAccessTokenRecoveryHandler {

    void handle(AccessTokenProvider accessTokenProvider, String authorizationHeader,  long currentTime);

}
