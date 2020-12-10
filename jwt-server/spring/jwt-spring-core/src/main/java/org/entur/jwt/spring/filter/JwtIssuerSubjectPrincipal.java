package org.entur.jwt.spring.filter;

import java.io.Serializable;

public class JwtIssuerSubjectPrincipal implements Serializable {

	private static final long serialVersionUID = 1L;
	
	private final String issuer;
	private final String subject;
	
	public JwtIssuerSubjectPrincipal(String issuer, String subject) {
		super();
		this.issuer = issuer;
		this.subject = subject;
	}
	
	public String getIssuer() {
		return issuer;
	}
	public String getSubject() {
		return subject;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((issuer == null) ? 0 : issuer.hashCode());
		result = prime * result + ((subject == null) ? 0 : subject.hashCode());
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
		JwtIssuerSubjectPrincipal other = (JwtIssuerSubjectPrincipal) obj;
		if (issuer == null) {
			if (other.issuer != null)
				return false;
		} else if (!issuer.equals(other.issuer))
			return false;
		if (subject == null) {
			if (other.subject != null)
				return false;
		} else if (!subject.equals(other.subject))
			return false;
		return true;
	}

	@Override
	public String toString() {
		return "IssuerSubjectPrincipal[" + issuer + " " + subject + "]";
	}
	
	
}
