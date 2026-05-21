package org.entur.jwt.spring;

import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.entur.jwt.spring.actuate.ListEventListener;
import org.springframework.beans.factory.DisposableBean;

import java.io.Closeable;
import java.io.IOException;
import java.util.Collections;
import java.util.Map;

public class JwkSourceMap<C extends SecurityContext> implements Closeable, DisposableBean {

    private final Map<String, JWKSource<C>> jwkSources;
    private final Map<String, ListEventListener> jwkEventListeners;

    @Deprecated
    public JwkSourceMap(Map<String, JWKSource<C>> jwkSources) {
        this(jwkSources, Collections.emptyMap());
    }

    public JwkSourceMap(Map<String, JWKSource<C>> jwkSources, Map<String, ListEventListener> jwkEventListeners) {
        this.jwkSources = jwkSources;
        this.jwkEventListeners = jwkEventListeners;
    }

    @Override
    public void close() throws IOException {
        for (Map.Entry<String, JWKSource<C>> jwkSourceEntry : jwkSources.entrySet()) {
            JWKSource<C> value = jwkSourceEntry.getValue();
            if(value instanceof Closeable) {
                Closeable closeable = (Closeable) value;

                closeable.close();
            }
        }
    }

    public Map<String, JWKSource<C>> getJwkSources() {
        return jwkSources;
    }

    @Override
    public void destroy() throws Exception {
        close();
    }

    public Map<String, ListEventListener> getJwkEventListeners() {
        return jwkEventListeners;
    }
}
