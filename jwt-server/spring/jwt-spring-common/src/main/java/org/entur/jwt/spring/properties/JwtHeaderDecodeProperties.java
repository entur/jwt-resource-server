package org.entur.jwt.spring.properties;

public class JwtHeaderDecodeProperties {

    private JwtHeaderDecodeMapHeaderToIssuerProperties mapHeaderToIssuer = new JwtHeaderDecodeMapHeaderToIssuerProperties();

    public void setMapHeaderToIssuer(JwtHeaderDecodeMapHeaderToIssuerProperties mapHeaderToIssuer) {
        this.mapHeaderToIssuer = mapHeaderToIssuer;
    }

    public JwtHeaderDecodeMapHeaderToIssuerProperties getMapHeaderToIssuer() {
        return mapHeaderToIssuer;
    }
}
