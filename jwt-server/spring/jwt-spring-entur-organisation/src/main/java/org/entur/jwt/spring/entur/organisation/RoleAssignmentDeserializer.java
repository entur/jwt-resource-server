package org.entur.jwt.spring.entur.organisation;

import java.io.IOException;
import java.util.Iterator;

import org.entur.jwt.spring.entur.organisation.RoleAssignment.Builder;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

/**
 * Json serializer which uses the builder.
 *
 */

public class RoleAssignmentDeserializer extends StdDeserializer<RoleAssignment> {
	
	private static final long serialVersionUID = 1L;
	
	protected RoleAssignmentDeserializer() {
		super(RoleAssignment.class);
	}

	@Override
	public RoleAssignment deserialize(JsonParser jp, DeserializationContext ctxt) throws IOException, JsonProcessingException {
		JsonNode node = jp.getCodec().readTree(jp);
		
		Builder builder = RoleAssignment.builder().withRole(node.get("r").asText()).withOrganisation(node.get("o").asText());

		if(node.has("z")) {
			builder.withAdministrativeZone(node.get("z").asText());
		}

		if(node.has("e")) {
			ObjectNode list = (ObjectNode) node.get("e");
			
			Iterator<String> fieldNames = list.fieldNames();
			while(fieldNames.hasNext()) {
				String entityType = fieldNames.next();
				ArrayNode entityClassifications = (ArrayNode) list.get(entityType);
				for(int i = 0;i < entityClassifications.size(); i++) {
					builder.withEntityClassification(entityType, entityClassifications.get(i).asText());
				}
			}
		}

		return builder.build();
	}
	
}