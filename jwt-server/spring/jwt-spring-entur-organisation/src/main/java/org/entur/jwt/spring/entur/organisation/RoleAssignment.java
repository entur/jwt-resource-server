/*
 * Licensed under the EUPL, Version 1.2 or – as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence");
 * You may not use this work except in compliance with the Licence.
 * You may obtain a copy of the Licence at:
 *
 *   https://joinup.ec.europa.eu/software/page/eupl
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 *
 */

package org.entur.jwt.spring.entur.organisation;


import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Representation of RoleAssignments. A list of these should be included in JWT as attribute "roles" under other claims.
 * <p>
 * Short attr names to keep JWT small.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonDeserialize(using = RoleAssignmentDeserializer.class)
public class RoleAssignment {

	/**
	 * Private code for role, required
	 */
	private String r;

	/**
	 * Private code for organisation, required
	 */
	private String o;

	/**
	 * Private code for administrative zone, optional
	 */
	private String z;

	/**
	 * Map of entity types (Stop place, PlaceOfInterest ... ) mapped against classifiers for the type (tramStop etc), each represented by private code. Optional.
	 */
	private Map<String, List<String>> e;

	@JsonProperty("r")
	public String getRole() {
		return r;
	}
	@JsonProperty("o")
	public String getOrganisation() {
		return o;
	}
	@JsonProperty("z")
	public String getAdministrativeZone() {
		return z;
	}
	@JsonProperty("e")
	public Map<String, List<String>> getEntityClassifications() {
		return e;
	}

	@Override
	public String toString() {
		return "RoleAssignment [r=" + r + ", o=" + o + ", z=" + z + ", e=" + e + "]";
	}
	public static Builder builder() {
		return new Builder();
	}

	public static class Builder {

		protected RoleAssignment roleAssignment = new RoleAssignment();

		private Builder() {
		}

		public Builder withRole(String role) {
			roleAssignment.r = role;
			return this;
		}

		public Builder withOrganisation(String organisation) {
			roleAssignment.o = organisation;
			return this;
		}

		public Builder withAdministrativeZone(String administrativeZone) {
			roleAssignment.z = administrativeZone;
			return this;
		}

		public Builder withEntityClassification(String entityType, String entityClassification) {
			if (roleAssignment.e == null) {
				roleAssignment.e = new HashMap<>();
			}
			List<String> classificationsForType = roleAssignment.e.get(entityType);
			if (classificationsForType == null) {
				classificationsForType = new ArrayList<>();
				roleAssignment.e.put(entityType, classificationsForType);
			}
			classificationsForType.add(entityClassification);
			return this;
		}

		public RoleAssignment build() {
			if (roleAssignment.r == null) {
				throw new IllegalArgumentException("No role (r) set");
			}
			if (roleAssignment.o == null) {
				throw new IllegalArgumentException("No organisation (o) set");
			}
			return roleAssignment;
		}
	}

	public String toJson() {
		ObjectMapper mapper = new ObjectMapper();

		try {
			return mapper.writeValueAsString(this);
		} catch (JsonProcessingException e1) {
			throw new IllegalArgumentException(e1);
		}
	}
	
	
}
