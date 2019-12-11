package org.entur.jwt.spring.entur.organisation;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.apache.commons.io.IOUtils;
import org.junit.jupiter.api.Test;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectReader;
import static com.google.common.truth.Truth.assertThat;

public class RoleAssignmentDeserializerTest {

    @Test
    public void testDeserializer() throws Exception {
        String body = IOUtils.resourceToString("/jwt.txt", StandardCharsets.UTF_8);

        ObjectMapper mapper = new ObjectMapper();

        Map<String, Object> token = mapper.readValue(body, Map.class);

        ObjectReader reader = mapper.readerFor(RoleAssignment.class);

        List<RoleAssignment> result = new ArrayList<>();

        List<String> roles = (List<String>) token.get("roles");
        assertThat(roles).hasSize(6);

        for (String role : roles) {
            result.add(reader.readValue(role));
        }

        assertThat(result.get(2).getRole()).isEqualTo("editStops");
        assertThat(result.get(2).getOrganisation()).isEqualTo("NSB");
        assertThat(result.get(2).getEntityClassifications().get("StopPlaceType")).containsExactly("*");

    }
}
