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

import java.util.List;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

public abstract class AbstractAuthorizationService {

	public AbstractAuthorizationService(RoleAssignmentExtractor roleAssignmentExtractor) {
		super();
		this.roleAssignmentExtractor = roleAssignmentExtractor;
	}

	protected RoleAssignmentExtractor roleAssignmentExtractor;

	public void verifyAtLeastOne(AuthorizationClaim... claims) {
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		verifyAtLeastOne(authentication, claims);
	}

	public void verifyAtLeastOne(Authentication authentication, AuthorizationClaim... claims) {
		List<RoleAssignment> roleAssignments = roleAssignmentExtractor.getRoleAssignmentsForUser(authentication);

		boolean authorized = false;
		for (AuthorizationClaim claim : claims) {
			if (claim.getProviderId() == null) {
				authorized |= roleAssignments.stream().anyMatch(ra -> claim.getRequiredRole().equals(ra.getRole()));
			} else {
				authorized |= hasRoleForProvider(roleAssignments, claim);
			}
		}

		if (!authorized) {
			throw new AccessDeniedException("Insufficient privileges for operation");
		}

	}

	protected abstract boolean hasRoleForProvider(List<RoleAssignment> roleAssignments, AuthorizationClaim claim);

}