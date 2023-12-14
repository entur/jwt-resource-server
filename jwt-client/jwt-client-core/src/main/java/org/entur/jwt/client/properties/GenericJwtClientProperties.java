package org.entur.jwt.client.properties;

public class GenericJwtClientProperties extends AbstractJwtClientProperties {
    protected String issuePath;
    protected String refreshPath;
    protected String revokePath;

    protected ClientSecretRequestFormat clientSecretRequestFormat = ClientSecretRequestFormat.URL_PARAMETERS;

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

    public ClientSecretRequestFormat getClientSecretRequestFormat() {
        return clientSecretRequestFormat;
    }

    public void setClientSecretRequestFormat(ClientSecretRequestFormat clientSecretRequestFormat) {
        this.clientSecretRequestFormat = clientSecretRequestFormat;
    }

    public enum ClientSecretRequestFormat {
        URL_PARAMETERS,
        AUTHORIZATION_HEADER
    }
}
