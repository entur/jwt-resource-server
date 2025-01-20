package org.entur.jwt.spring.grpc;

/**
 *
 * Interface for submitting key-values to a gRPC equivalent of the MDC.
 *
 */

public interface GrpcMdcAdapter {

    void put(String key, String value);

    void remove(String key);

    String get(String key);

    void clear();

}
