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


import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.entur.jwt.spring.filter.JwtAuthenticationToken;
import org.entur.jwt.verifier.JwtClaimException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Extract RoleAssignments from JwtAuthenticationToken.
 */
public class JwtRoleAssignmentExtractor implements RoleAssignmentExtractor {

    private static final String ATTRIBUTE_NAME_ROLE_ASSIGNMENT = "roles";
    private static ObjectMapper mapper = new ObjectMapper();

    public List<RoleAssignment> getRoleAssignmentsForUser() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        return getRoleAssignmentsForUser(auth);
    }

    @Override
    public List<RoleAssignment> getRoleAssignmentsForUser(Authentication auth) {
        if (auth instanceof JwtAuthenticationToken) {
        	JwtAuthenticationToken jwt = (JwtAuthenticationToken)auth;
        	
        	List<?> claim;
			try {
				claim = jwt.getClaim(ATTRIBUTE_NAME_ROLE_ASSIGNMENT, List.class);
			} catch (JwtClaimException e) {
                throw new IllegalArgumentException("Unsupported 'roles' claim type.", e);
			}
			if(claim == null || claim.isEmpty()) {
                throw new IllegalArgumentException("Unsupported 'roles' claim type.");
			}

            return claim.stream().map(m -> parse(m)).collect(Collectors.toList());
        } else {
            throw new AccessDeniedException("Not authenticated with token");
        }
    }

    private RoleAssignment parse(Object roleAssignment) {
        if (roleAssignment instanceof Map) {
            return mapper.convertValue(roleAssignment, RoleAssignment.class);
        }
        try {
            return mapper.readValue((String) roleAssignment, RoleAssignment.class);
        } catch (IOException ioE) {
            throw new RuntimeException("Exception while parsing role assignments from JSON: " + ioE.getMessage(), ioE);
        }
    }
}
