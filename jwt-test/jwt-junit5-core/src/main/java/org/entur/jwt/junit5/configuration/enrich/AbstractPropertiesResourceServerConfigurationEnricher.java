package org.entur.jwt.junit5.configuration.enrich;

import java.io.BufferedWriter;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.entur.jwt.junit5.AuthorizationServer;
import org.entur.jwt.junit5.impl.AuthorizationServerImplementation;
import org.entur.jwt.junit5.impl.AuthorizationServerImplementationFactory;

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
