package org.entur.jwt.client;

import java.net.URL;
import java.util.Map;

public interface ClientCredentials {

    URL getIssueURL();

    URL getRefreshURL();

    URL getRevokeURL();

    Map<String, Object> getParameters();

    Map<String, Object> getHeaders();
}
