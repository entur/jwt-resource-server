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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Service;

import java.lang.reflect.Field;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static java.util.stream.Collectors.toList;
import static org.entur.jwt.spring.entur.organisation.AuthorizationConstants.*;

@Service
public class ReflectionAuthorizationService {

    private static final Logger logger = LoggerFactory.getLogger(ReflectionAuthorizationService.class);

    private final RoleAssignmentExtractor roleAssignmentExtractor;

    private final boolean authorizationEnabled;

    private final OrganisationChecker organisationChecker;

    private final AdministrativeZoneChecker administrativeZoneChecker;

    private final EntityResolver entityResolver;

    /**
     * TODO: Keys needs to be added lower case. Find a better solution to this.
     */
    private final Map<String, List<String>> fieldMappings;

    public ReflectionAuthorizationService(RoleAssignmentExtractor roleAssignmentExtractor,
                                          boolean authorizationEnabled,
                                          OrganisationChecker organisationChecker,
                                          AdministrativeZoneChecker administrativeZoneChecker,
                                          EntityResolver entityResolver,
                                          Map<String, List<String>> fieldMappings) {
        this.roleAssignmentExtractor = roleAssignmentExtractor;
        this.authorizationEnabled = authorizationEnabled;
        this.organisationChecker = organisationChecker;
        this.administrativeZoneChecker = administrativeZoneChecker;
        this.entityResolver = entityResolver;
        this.fieldMappings = fieldMappings;
    }

    public void assertAuthorized(String requiredRole, Collection<?> entities) {

        final boolean allowed = isAuthorized(requiredRole, entities);
        if (!allowed) {
            throw new AccessDeniedException("Insufficient privileges for operation");
        }
    }


    public boolean isAuthorized(String requiredRole, Collection<?> entities) {
        if (!authorizationEnabled) {
            return true;
        }

        logger.debug("Checking if authorized for entities: {}", entities);

        List<RoleAssignment> relevantRoles = roleAssignmentExtractor.getRoleAssignmentsForUser()
                .stream()
                .filter(roleAssignment -> requiredRole.equals(roleAssignment.r))
                .collect(toList());

        for (Object entity : entities) {
            boolean allowed = entity == null ||
                    relevantRoles
                            .stream()
                            // Only one of the role assignments needs to match for the given entity and required role
                            .anyMatch(roleAssignment -> authorized(roleAssignment, entity, requiredRole));
            if (!allowed) {
                // No need to loop further, if not authorized with required role for one of the entities in collection.
                logger.info("User is not authorized for entity with role: {}. Relevant roles: {}. Entity: {}", requiredRole, relevantRoles, entity);
                return false;
            }

        }
        return true;
    }

    public Set<String> getRelevantRolesForEntity(Object entity) {
        return roleAssignmentExtractor.getRoleAssignmentsForUser().stream()
                .filter(roleAssignment -> roleAssignment.getEntityClassifications().get(ENTITY_TYPE).stream()
                        .anyMatch(entityTypeString -> entityTypeString.toLowerCase().equals(entity.getClass().getSimpleName().toLowerCase())
                                || entityTypeString.contains(ENTITY_CLASSIFIER_ALL_TYPES)))
                .map(roleAssignment -> roleAssignment.getRole())
                .collect(Collectors.toSet());
    }

    public boolean authorized(RoleAssignment roleAssignment, Object entity, String requiredRole) {

        entity = entityResolver.resolveCorrectEntity(entity);

        if (roleAssignment.getEntityClassifications() == null) {
            logger.warn("Role assignment entity classifications cannot be null: {}", roleAssignment);
            return false;
        }

        if (!roleAssignment.getRole().equals(requiredRole)) {
            logger.debug("No role match for required role {}, {}", requiredRole, roleAssignment);
            return false;
        }

        if (!organisationChecker.entityMatchesOrganisationRef(roleAssignment, entity)) {
            logger.debug("Entity does not match organization ref. RoleAssignment: {}, Entity: {}", roleAssignment, entity);
            return false;
        }

        String entityTypename = entity.getClass().getSimpleName();

        if (!checkEntityClassifications(entityTypename, entity, roleAssignment, requiredRole)) {
            logger.debug("Entity classification. Not authorized: {}, {}", requiredRole, roleAssignment);
            return false;
        }

        if (!checkAdministrativeZone(roleAssignment, entity)) {
            logger.debug("Entity type administrative zone no match: {} entity: {}", roleAssignment, entity);
            return false;
        }

        return true;
    }

    private boolean checkEntityClassifications(String entityTypename, Object entity, RoleAssignment roleAssignment, String requiredRole) {

        if (!containsEntityTypeOrAll(roleAssignment, entityTypename)) {
            logger.debug("No match for entity type {} for required role {}. Role assignment: {}",
                    entity.getClass().getSimpleName(), requiredRole, roleAssignment);
            return false;
        }

        for (String entityType : roleAssignment.getEntityClassifications().keySet()) {
            boolean authorized = checkEntityClassification(entityType, entity, roleAssignment.getEntityClassifications().get(entityType));

            if (!authorized) {
                logger.info("Not authorized for entity {} and role assignment {}", entity, roleAssignment);
                return false;
            }

        }
        return true;
    }

    private boolean checkEntityClassification(String entityType, Object entity, List<String> classificationsForEntityType) {
        if (entityType.equals(ENTITY_TYPE)) {
            // Already checked
            return true;
        }

        if (classificationsForEntityType.contains(ENTITY_CLASSIFIER_ALL_ATTRIBUTES)) {
            logger.debug("Contains {} for {}", ENTITY_CLASSIFIER_ALL_ATTRIBUTES, entityType);
            return true;

        }


        boolean isBlacklist = classificationsForEntityType.stream().anyMatch(classifier -> classifier.startsWith("!"));
        boolean isWhiteList = classificationsForEntityType.stream().noneMatch(classifier -> classifier.startsWith("!"));

        if (isBlacklist && isWhiteList) {
            logger.warn("The list of classifiers contains values with both black list values (values prefixed with !) and white list values. This is not supported");
            return false;
        }

        List<String> mappings = fieldMappings.get(entityType.toLowerCase());
        if (mappings != null) {
            logger.debug("Found mapped value from {} to {}", entityType, mappings);

            if (isBlacklist) {
                // If the list is detected to be blacklist values, every mapped field must match.
                return mappings.stream()
                        .allMatch(mappedField -> isAllowedForFieldAndClassification(mappedField, entity, classificationsForEntityType, true));
            } else {
                // If the list is detected to be a white list, any match is enough.
                return mappings.stream()
                        .anyMatch(mappedField -> isAllowedForFieldAndClassification(mappedField, entity, classificationsForEntityType, false));
            }
        } else {
            return isAllowedForFieldAndClassification(entityType, entity, classificationsForEntityType, isBlacklist);
        }
    }

    private boolean isAllowedForFieldAndClassification(String entityType, Object entity, List<String> classificationsForEntityType, boolean isBlacklist) {
        Optional<Field> optionalField = findFieldFromClassifier(entityType, entity);

        if (!optionalField.isPresent()) {
            logger.warn("Cannot fetch field {}. entity: {}", entityType, entity);
            return true;
        }

        Field field = optionalField.get();

        logger.debug("Found field {} from classifier {}", field, entityType);

        field.setAccessible(true);
        Optional<Object> optionalValue = getFieldValue(field, entity);

        if (!optionalValue.isPresent()) {
            logger.trace("Cannot resolve value for {}. This is ok, as the value can be null. entity: {}.", field, entity);
            return isBlacklist;
        }

        Object value = optionalValue.get();
        String stringValue = removeUnderscore(value.toString());

        boolean isAllowed;
        if (isBlacklist) {

            isAllowed = classificationsForEntityType.stream()
                    .noneMatch(classification ->
                            removeUnderscore(classification.substring(1))
                                    .equalsIgnoreCase(stringValue));


        } else {
            isAllowed = classificationsForEntityType.stream()
                    .anyMatch(classification ->
                            removeUnderscore(classification)
                                    .equalsIgnoreCase(stringValue));


        }

        if (!isAllowed) {
            logger.info("Not allowed value {}: {} for entity {}", entityType, value, entity);
            return false;
        }
        logger.debug("Allowed value {}: {} for entity {}", entityType, value, entity);
        return true;
    }

    private Optional<Field> findFieldFromClassifier(String classifier, Object entity) {
        return Stream.of(entity.getClass().getDeclaredFields())
                .filter(field -> classifier.equalsIgnoreCase(field.getName()))
                .findFirst();
    }

    private Optional<Object> getFieldValue(Field field, Object object) {
        try {
            return Optional.ofNullable(field.get(object));
        } catch (IllegalAccessException e) {
            logger.warn("Could not access field value {} - {}", field, object);
            return Optional.empty();
        }
    }

    private String removeUnderscore(String string) {
        return string.replaceAll("_", "");
    }

    public boolean checkAdministrativeZone(RoleAssignment roleAssignment, Object entity) {
        return roleAssignment.getAdministrativeZone() == null
                || roleAssignment.getAdministrativeZone().isEmpty()
                || administrativeZoneChecker.entityMatchesAdministrativeZone(roleAssignment, entity);
    }

    private boolean containsEntityTypeOrAll(RoleAssignment roleAssignment, String entityTypeName) {

        List<String> classifiers = roleAssignment.getEntityClassifications().get(ENTITY_TYPE);

        if (classifiers == null || classifiers.isEmpty()) {
            logger.warn("Classifiers is empty for {}", ENTITY_TYPE);
            return false;
        }

        for (String entityType : classifiers) {
            if (entityType.equalsIgnoreCase(entityTypeName)) {
                return true;
            }
            if (ENTITY_CLASSIFIER_ALL_TYPES.equals(entityType)) {
                return true;
            }
        }

        return false;
    }
}
