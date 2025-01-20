package org.entur.jwt.spring.grpc;

import java.util.concurrent.Executor;

import io.grpc.CallCredentials;
import io.grpc.Metadata;

public class JwtCallCredentials extends CallCredentials {
    
    private final String token;

    public JwtCallCredentials(String token) {
        super();
        this.token = token;
    }

    @Override
    public void applyRequestMetadata(RequestInfo requestInfo, Executor executor, MetadataApplier metadataApplier) {
        executor.execute(new Runnable() {
            @Override
            public void run() {
                try {
                    Metadata headers = new Metadata();
                    Metadata.Key<String> jwtKey = Metadata.Key.of("Authorization", Metadata.ASCII_STRING_MARSHALLER);
                    headers.put(jwtKey, token);
                    metadataApplier.apply(headers);
                } catch (Throwable e) {
                    throw new RuntimeException(e);
                }
            }
        });
    }

    @Override
    public void thisUsesUnstableApi() {
        // do nothing
    }
}
