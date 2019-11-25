package org.entur.jwt.junit5.extention;

import java.lang.annotation.Annotation;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import org.entur.jwt.junit5.AuthorizationServerEncoder;
import org.entur.jwt.junit5.impl.AuthorizationServerImplementation;

public class AuthorizationServerTestContext {

	private Map<Annotation, AuthorizationServerImplementation> authorizationServers;

	public AuthorizationServerTestContext(List<AuthorizationServerImplementation> list) {
		super();

		Map<Annotation, AuthorizationServerImplementation> values = new HashMap<>();
		for (AuthorizationServerImplementation item : list) {
			values.put(item.getAnnotation(), item);
		}

		this.authorizationServers = values;
	}

	public AuthorizationServerEncoder getEncoder(AuthorizationServerImplementation impl) {
		return authorizationServers.get(impl.getAnnotation()).getEncoder();
	}

	public boolean isDirty(List<AuthorizationServerImplementation> current) {
		if (current.size() != authorizationServers.size()) {
			return true;
		}

		Set<Annotation> currentKeys = current.stream().map(AuthorizationServerImplementation::getAnnotation).collect(Collectors.toSet());

		return !currentKeys.containsAll(authorizationServers.keySet());
	}

	public List<AuthorizationServerImplementation> toList() {
		return new ArrayList<>(authorizationServers.values());
	}
}
