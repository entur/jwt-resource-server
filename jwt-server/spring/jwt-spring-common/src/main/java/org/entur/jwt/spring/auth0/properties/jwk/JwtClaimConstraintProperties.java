package org.entur.jwt.spring.auth0.properties.jwk;

public class JwtClaimConstraintProperties {

    private String name;
    private String value; // optional
    private String type; // i.e. number, tree, text etc

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public void setValue(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}
