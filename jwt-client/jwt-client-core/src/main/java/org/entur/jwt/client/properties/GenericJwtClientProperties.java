package org.entur.jwt.client.properties;

public class GenericJwtClientProperties extends AbstractJwtClientProperties {
    protected String issuePath;
    protected String refreshPath;
    protected String revokePath;

    protected ClientCredentialsRequestFormat clientCredentialsRequestFormat = ClientCredentialsRequestFormat.URL_PARAMETERS;

    public String getIssuePath() {
        return issuePath;
    }

    public void setIssuePath(String issuePath) {
        this.issuePath = issuePath;
    }

    public String getRefreshPath() {
        return refreshPath;
    }

    public void setRefreshPath(String refreshPath) {
        this.refreshPath = refreshPath;
    }

    public String getRevokePath() {
        return revokePath;
    }

    public void setRevokePath(String revokePath) {
        this.revokePath = revokePath;
    }

    public ClientCredentialsRequestFormat getClientCredentialsRequestFormat() {
        return clientCredentialsRequestFormat;
    }

    public void setClientCredentialsRequestFormat(ClientCredentialsRequestFormat clientCredentialsRequestFormat) {
        this.clientCredentialsRequestFormat = clientCredentialsRequestFormat;
    }

    public enum ClientCredentialsRequestFormat {
        URL_PARAMETERS,
        AUTHORIZATION_HEADER
    }
}
