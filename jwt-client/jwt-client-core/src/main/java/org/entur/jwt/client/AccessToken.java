package org.entur.jwt.client;

import java.io.Serializable;

public class AccessToken implements Serializable {

    private static final long serialVersionUID = 1L;

    public static AccessToken newInstance(String value, String type, long expires) {
        return new AccessToken(value, type, expires);
    }

    protected final String value;
    protected final String type;
    protected final long expires;

    public AccessToken(String value, String type, long expiresAt) {
        super();
        this.value = value;
        this.type = type;
        this.expires = expiresAt;
    }

    public String getValue() {
        return value;
    }

    public String getType() {
        return type;
    }

    public long getExpires() {
        return expires;
    }

    public boolean isValid(long time) {
        return time <= expires;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + (int) (expires ^ (expires >>> 32));
        result = prime * result + ((type == null) ? 0 : type.hashCode());
        result = prime * result + ((value == null) ? 0 : value.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        AccessToken other = (AccessToken) obj;
        if (expires != other.expires)
            return false;
        if (type == null) {
            if (other.type != null)
                return false;
        } else if (!type.equals(other.type)) {
            return false;
        }
        if (value == null) {
            if (other.value != null)
                return false;
        } else if (!value.equals(other.value)) {
            return false;
        }
        return true;
    }

}