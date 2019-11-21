package org.entur.jwt.spring.properties;

import java.util.ArrayList;
import java.util.List;

public class AuthorizationProperties {

	private String mode = "optional"; // optional or required;
	
	/** Simple path filter. Effectively refuse requests with paths not included in this list. */
	private List<String> filter = new ArrayList<>();

	public String getMode() {
		return mode;
	}

	public void setMode(String mode) {
		this.mode = mode;
	}

	public List<String> getFilter() {
		return filter;
	}
	
	public void setFilter(List<String> filter) {
		this.filter = filter;
	}
	
	
}
