package org.entur.jwt.spring;

import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.beans.factory.DisposableBean;

import java.io.Closeable;
import java.io.IOException;
import java.util.Map;

public class JwkSourceMap<C extends SecurityContext> implements Closeable, DisposableBean {

    private final Map<String, JWKSource<C>> jwkSources;

    public JwkSourceMap(Map<String, JWKSource<C>> jwkSources) {
        this.jwkSources = jwkSources;
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
}
