package org.entur.jwt.junit5.configuration.enrich;

import org.entur.jwt.junit5.impl.AuthorizationServerImplementation;
import org.entur.jwt.junit5.impl.AuthorizationServerImplementationFactory;

import java.io.IOException;
import java.util.List;
import java.util.Map;

public abstract class AbstractPropertiesResourceServerConfigurationEnricher implements ResourceServerConfigurationEnricher {

    protected String prefix;

    public AbstractPropertiesResourceServerConfigurationEnricher() throws IOException {
        this("entur.jwt.tenants");
    }

    public AbstractPropertiesResourceServerConfigurationEnricher(String prefix) {
        this.prefix = prefix;
    }

    public void setPrefix(String prefix) {
        this.prefix = prefix;
    }

    protected Map<String, Object> getProperties(List<AuthorizationServerImplementation> implementations) throws IOException {
        return AuthorizationServerImplementationFactory.getProperties(prefix, implementations);
    }

}
