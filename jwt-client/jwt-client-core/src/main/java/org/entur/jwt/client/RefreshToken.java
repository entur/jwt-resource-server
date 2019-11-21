package org.entur.jwt.client;

public class RefreshToken {

    private final String value;
    // non-standard claim
    private final long expires;

	public RefreshToken(String refreshToken, long expiresAt) {
		super();
		this.value = refreshToken;
		this.expires = expiresAt;
	}

	public String getValue() {
		return value;
	}

	public long getExpires() {
		return expires;
	}
	
    public boolean isValid(long time) {
        return expires == -1L || time <= expires;
    }
    
}