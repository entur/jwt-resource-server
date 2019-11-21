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

import com.google.common.base.MoreObjects;
import org.junit.Test;
import org.springframework.security.core.Authentication;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static java.util.stream.Collectors.toList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;
import static org.entur.jwt.spring.entur.organisation.AuthorizationConstants.ENTITY_TYPE;

/**
 * Example content for token's role assignment.
 * [
 * {
 * “r”: “editStops”,
 * “o”: “OST”,
 * “z”: “01",
 * “e”: {
 * “EntityType”: [
 * “StopPlace”, "Parking" {
 * ],
 * “StopPlaceType”: [
 * “!airport”,
 * “!railStation”
 * ],
 * versionComment
 * “Submode”: [
 * “!railReplacementBus”
 * ]
 * }
 * }
 * ]
 */
public class ReflectionAuthorizationServiceTest {


    private RoleAssignmentExtractor roleAssignmentExtractor = new RoleAssignmentExtractor() {
        @Override
        public List<RoleAssignment> getRoleAssignmentsForUser() {
            return null;
        }

        @Override
        public List<RoleAssignment> getRoleAssignmentsForUser(Authentication authentication) {
            return null;
        }
    };

    private OrganisationChecker organisationChecker = (roleAssignment, entity) -> true;
    private AdministrativeZoneChecker administrativeZoneChecker = (roleAssignment, entity) -> true;
    private EntityResolver entityResolver = (entity -> entity);
    private Map<String, List<String>> fieldMappings = new HashMap<>();

    private ReflectionAuthorizationService reflectionAuthorizationService = new ReflectionAuthorizationService(roleAssignmentExtractor, true, organisationChecker, administrativeZoneChecker, entityResolver, fieldMappings);

    @Test
    public void authorizedForLegalStopPlaceTypesWhenOthersBlacklisted() {
        RoleAssignment roleAssignment = RoleAssignment.builder()
                .withRole("editStops")
                .withAdministrativeZone("01")
                .withOrganisation("OST")
                .withEntityClassification(ENTITY_TYPE, "StopPlace")
                .withEntityClassification("StopPlaceType", "!airport")
                .withEntityClassification("StopPlaceType", "!railStation")
                .build();

        StopPlace stopPlace = new StopPlace();
        stopPlace.stopPlaceType = StopPlace.StopPlaceType.ONSTREET_BUS;

        boolean authorized = reflectionAuthorizationService.authorized(roleAssignment, stopPlace, roleAssignment.r);
        assertThat(authorized, is(true));
    }

    /**
     * EntityType=StopPlace, StopPlaceType=!railStation,!airport, Submode=!railReplacementBus
     */
    @Test
    public void authorizedWithCombinationOfTwoFields() {

        StopPlace stopPlace = new StopPlace();
        stopPlace.stopPlaceType = StopPlace.StopPlaceType.ONSTREET_BUS;
        stopPlace.someField1 = "nationalPassengerFerry";

        RoleAssignment roleAssignment = RoleAssignment.builder()
                .withRole("editStops")
                .withAdministrativeZone("01")
                .withOrganisation("OST")
                .withEntityClassification(ENTITY_TYPE, "StopPlace")
                .withEntityClassification("StopPlaceType", "!railStation")
                .withEntityClassification("StopPlaceType", "!airport")
                .withEntityClassification("combinedField", "!railReplacementBus")
                .build();

        fieldMappings.put("combinedfield", Arrays.asList("someField1"));

        boolean authorized = reflectionAuthorizationService.authorized(roleAssignment, stopPlace, roleAssignment.r);
        assertThat(authorized, is(true));
    }

    @Test
    public void notAuthorizedWithCombinationOfNegatedTwoFields() {

        String railReplacementBus = "railReplacementBus";

        StopPlace stopPlace = new StopPlace();
        stopPlace.stopPlaceType = StopPlace.StopPlaceType.ONSTREET_BUS;
        stopPlace.someField1 = railReplacementBus;

        RoleAssignment roleAssignment = RoleAssignment.builder()
                .withRole("editStops")
                .withAdministrativeZone("01")
                .withOrganisation("OST")
                .withEntityClassification(ENTITY_TYPE, "StopPlace")
                .withEntityClassification("StopPlaceType", "!railStation")
                .withEntityClassification("StopPlaceType", "!airport")
                .withEntityClassification("combinedField", "!"+railReplacementBus)
                .build();

        fieldMappings.put("combinedfield", Arrays.asList("someField1"));

        boolean authorized = reflectionAuthorizationService.authorized(roleAssignment, stopPlace, roleAssignment.r);
        assertThat(railReplacementBus + " not allowed for combinedField", authorized, is(false));
    }

    @Test
    public void notAuthorizedWithCombinationOfNegatedTwoFields2() {

        StopPlace stopPlace = new StopPlace();
        stopPlace.stopPlaceType = StopPlace.StopPlaceType.AIRPORT;
        stopPlace.someField1 = "localCarFerry";

        RoleAssignment roleAssignment = RoleAssignment.builder()
                .withRole("editStops")
                .withAdministrativeZone("01")
                .withOrganisation("OST")
                .withEntityClassification(ENTITY_TYPE, "StopPlace")
                .withEntityClassification("StopPlaceType", "!railStation")
                .withEntityClassification("StopPlaceType", "!airport")
                .withEntityClassification("combinedField", "!railReplacementBus")
                .build();

        fieldMappings.put("combinedfield", Arrays.asList("someField1"));

        boolean authorized = reflectionAuthorizationService.authorized(roleAssignment, stopPlace, roleAssignment.r);
        assertThat("airport not allowed for stop place type", authorized, is(false));
    }

    @Test
    public void notAuthorizedWithCombinationOfNegatedTwoFields3() {

        StopPlace stopPlace = new StopPlace();
        stopPlace.stopPlaceType = StopPlace.StopPlaceType.AIRPORT;
        stopPlace.someField1 = "railReplacementBus";

        RoleAssignment roleAssignment = RoleAssignment.builder()
                .withRole("editStops")
                .withAdministrativeZone("01")
                .withOrganisation("OST")
                .withEntityClassification(ENTITY_TYPE, "StopPlace")
                .withEntityClassification("StopPlaceType", "!railStation")
                .withEntityClassification("StopPlaceType", "!airport")
                // railReplacementBus allowed
                .withEntityClassification("combinedField", "railReplacementBus")
                .build();

        fieldMappings.put("combinedfield", Arrays.asList("someField1"));

        boolean authorized = reflectionAuthorizationService.authorized(roleAssignment, stopPlace, roleAssignment.r);
        assertThat("railReplacementBus allowed, but not stop place type airport", authorized, is(false));
    }

    @Test
    public void handleMappedClassificationsNegation() {

        StopPlace stopPlace = new StopPlace();
        stopPlace.someField1 = "someval1";
        stopPlace.someField2 = "someval2";
        // The entity has someField1 and someFieldf2 mapped by anotherProperty

        fieldMappings.put("anotherproperty", Arrays.asList("someField1", "someField2"));

        RoleAssignment roleAssignment = RoleAssignment.builder()
                .withRole("editStops")
                .withOrganisation("OST")
                .withAdministrativeZone("01")
                .withEntityClassification(ENTITY_TYPE, "StopPlace")
                // classification anotherProperty mapping should lead to someField1 and someField2
                .withEntityClassification("anotherProperty", "!someval2")
                .build();

        boolean authorized = reflectionAuthorizationService.authorized(roleAssignment, stopPlace, roleAssignment.r);
        assertThat(authorized, is(false));
    }

    @Test
    public void handleMappedClassifications() {

        StopPlace stopPlace = new StopPlace();
        stopPlace.someField1 = "someval1";
        stopPlace.someField2 = "someval2";

        fieldMappings.put("anotherproperty", Arrays.asList("someField1", "someField2"));

        RoleAssignment roleAssignment = RoleAssignment.builder()
                .withRole("editStops")
                .withOrganisation("OST")
                .withAdministrativeZone("01")
                .withEntityClassification(ENTITY_TYPE, "StopPlace")
                .withEntityClassification("anotherProperty", "someval2")
                .build();

        boolean authorized = reflectionAuthorizationService.authorized(roleAssignment, stopPlace, roleAssignment.r);
        assertThat("someval2 should be allowed for anotherProperty", authorized, is(true));
    }

    @Test
    public void authorizedForLegalSubmodeTypesWhenStarValue() {
        RoleAssignment roleAssignment = RoleAssignment.builder()
                .withRole("editStops")
                .withOrganisation("OST")
                .withAdministrativeZone("01")
                .withEntityClassification(ENTITY_TYPE, "StopPlace")
                .withEntityClassification("Submode", "*")
                .build();

        StopPlace stopPlace = new StopPlace();
        stopPlace.submode = "someValue";

        assertThat(reflectionAuthorizationService.authorized(roleAssignment, stopPlace, "editStops"), is(true));
    }

    @Test
    public void shouldBeAuthorizedForSubmodeTypesWhenExplicitWhiteListed() {
        RoleAssignment roleAssignment = RoleAssignment.builder()
                .withRole("editStops")
                .withOrganisation("OST")
                .withAdministrativeZone("01")
                .withEntityClassification(ENTITY_TYPE, "StopPlace")
                .withEntityClassification("Submode", "someValue")
                .build();

        StopPlace stopPlace = new StopPlace();
        stopPlace.submode = "someValue";

        assertThat(reflectionAuthorizationService.authorized(roleAssignment, stopPlace, "editStops"), is(true));
    }

    @Test
    public void notAuthorizedForSubmodeTypesWhenExplicitWhiteListed() {
        RoleAssignment roleAssignment = RoleAssignment.builder()
                .withRole("editStops")
                .withOrganisation("OST")
                .withAdministrativeZone("01")
                .withEntityClassification(ENTITY_TYPE, "StopPlace")
                .withEntityClassification("Submode", "someValue")
                .build();

        StopPlace stopPlace = new StopPlace();
        stopPlace.submode = "anotherValue";

        assertThat(reflectionAuthorizationService.authorized(roleAssignment, stopPlace, "editStops"), is(false));
    }

    @Test
    public void authorizedWhenAllTypesEntityType() {
        RoleAssignment roleAssignment = RoleAssignment.builder()
                .withRole("viewStops")
                .withAdministrativeZone("01")
                .withOrganisation("OST")
                .withEntityClassification(ENTITY_TYPE, "*")
                .build();

        boolean authorized = reflectionAuthorizationService.authorized(roleAssignment, new Object(), roleAssignment.r);
        assertThat(authorized, is(true));
    }

    @Test
    public void notAuthorizedWhenRolesMismatch() {
        RoleAssignment roleAssignment = RoleAssignment.builder()
                .withRole("viewStops")
                .withAdministrativeZone("01")
                .withOrganisation("OST")
                .withEntityClassification(ENTITY_TYPE, "*")
                .build();

        boolean authorized = reflectionAuthorizationService.authorized(roleAssignment, new Object(), "somethingElse");
        assertThat(authorized, is(false));
    }

    @Test
    public void notAuthorizedWhenEmptyRoleAssignmentEntityClassifications() {
        RoleAssignment roleAssignment = RoleAssignment.builder()
                .withRole("viewStops")
                .withAdministrativeZone("01")
                .withOrganisation("OST")
                .build();

        boolean authorized = reflectionAuthorizationService.authorized(roleAssignment, new Object(), roleAssignment.r);
        assertThat(authorized, is(false));
    }

    @Test
    public void notAuthorizedForIncorrectSubMode() {
        RoleAssignment roleAssignment = RoleAssignment.builder()
                .withRole("editStops")
                .withAdministrativeZone("01")
                .withOrganisation("OST")
                .withEntityClassification(ENTITY_TYPE, "StopPlace")
                .withEntityClassification("Submode", "!railReplacementBus")
                .build();

        StopPlace stopPlace = new StopPlace();
        stopPlace.stopPlaceType = StopPlace.StopPlaceType.AIRPORT;

        // Submode is not allowed
        stopPlace.submode = "railReplacementBus";

        boolean authorized = reflectionAuthorizationService.authorized(roleAssignment, stopPlace, roleAssignment.r);
        assertThat(authorized, is(false));
    }

    @Test
    public void notAuthorizedForIncorrectEntityType() {
        RoleAssignment roleAssignment = RoleAssignment.builder()
                .withRole("viewStops")
                .withAdministrativeZone("01")
                .withOrganisation("OST")
                .withEntityClassification(ENTITY_TYPE, "StopPlace")
                .build();

        // Not stop place
        Object object = new Object();

        boolean authorized = reflectionAuthorizationService.authorized(roleAssignment, object, roleAssignment.r);
        assertThat(authorized, is(false));
    }

    @Test
    public void notAuthorizedToEditAirport() {
        RoleAssignment roleAssignment = RoleAssignment.builder()
                .withRole("editStops")
                .withAdministrativeZone("01")
                .withOrganisation("OST")
                .withEntityClassification(ENTITY_TYPE, "StopPlace")
                .withEntityClassification("StopPlaceType", "!airport")
                .build();

        StopPlace stopPlace = new StopPlace();
        stopPlace.stopPlaceType = StopPlace.StopPlaceType.AIRPORT;

        boolean authorized = reflectionAuthorizationService.authorized(roleAssignment, stopPlace, roleAssignment.r);
        assertThat(authorized, is(false));
    }

    @Test
    public void notAuthorizedWhenValueEmpty() {
        RoleAssignment roleAssignment = RoleAssignment.builder()
                .withRole("editStops")
                .withAdministrativeZone("01")
                .withOrganisation("OST")
                .withEntityClassification(ENTITY_TYPE, "StopPlace")
                .withEntityClassification("StopPlaceType", "!airport")
                .build();

        StopPlace stopPlace = new StopPlace();

        boolean authorized = reflectionAuthorizationService.authorized(roleAssignment, stopPlace, roleAssignment.r);
        assertThat("stop place type is not set, which means that it's not airport", authorized, is(true));
    }

    /**
     * Onstreet bus does does contain underscore.
     */
    @Test
    public void notAuthorizedToEditOnstreetBus() {
        RoleAssignment roleAssignment = RoleAssignment.builder()
                .withRole("editStops")
                .withAdministrativeZone("01")
                .withOrganisation("OST")
                .withEntityClassification(ENTITY_TYPE, "StopPlace")
                .withEntityClassification("StopPlaceType", "!onstreetBus")
                .build();

        StopPlace stopPlace = new StopPlace();
        stopPlace.stopPlaceType = StopPlace.StopPlaceType.ONSTREET_BUS;

        boolean authorized = reflectionAuthorizationService.authorized(roleAssignment, stopPlace, roleAssignment.r);
        assertThat(authorized, is(false));
    }

    @Test
    public void notAuthorizedToEditWhenOneBlacklisted() {
        RoleAssignment roleAssignment = RoleAssignment.builder()
                .withRole("editStops")
                .withAdministrativeZone("01")
                .withOrganisation("OST")
                .withEntityClassification(ENTITY_TYPE, "StopPlace")
                .withEntityClassification("StopPlaceType", "!airport")
                .withEntityClassification("StopPlaceType", "!onstreetBus")
                .build();

        StopPlace stopPlace = new StopPlace();
        stopPlace.stopPlaceType = StopPlace.StopPlaceType.ONSTREET_BUS;

        boolean authorized = reflectionAuthorizationService.authorized(roleAssignment, stopPlace, roleAssignment.r);
        assertThat(authorized, is(false));
    }

    @Test
    public void notAuthorizedToEditWhenNoNegation() {
        RoleAssignment roleAssignment = RoleAssignment.builder()
                .withRole("editStops")
                .withAdministrativeZone("01")
                .withOrganisation("OST")
                .withEntityClassification(ENTITY_TYPE, "StopPlace")
                .withEntityClassification("StopPlaceType", "airport")
                .build();

        StopPlace stopPlace = new StopPlace();
        stopPlace.stopPlaceType = StopPlace.StopPlaceType.ONSTREET_BUS;

        boolean authorized = reflectionAuthorizationService.authorized(roleAssignment, stopPlace, roleAssignment.r);
        assertThat(authorized, is(false));
    }

    @Test
    public void notAuthorizedToEditWhenEnumValueContainsUnderscore() {
        RoleAssignment roleAssignment = RoleAssignment.builder()
                .withRole("editStops")
                .withAdministrativeZone("01")
                .withOrganisation("OST")
                .withEntityClassification(ENTITY_TYPE, "StopPlace")
                .withEntityClassification("StopPlaceType", "!onstreet_Bus")
                .build();

        StopPlace stopPlace = new StopPlace();
        stopPlace.stopPlaceType = StopPlace.StopPlaceType.ONSTREET_BUS;

        boolean authorized = reflectionAuthorizationService.authorized(roleAssignment, stopPlace, roleAssignment.r);
        assertThat(authorized, is(false));
    }

    @Test
    public void multipleEnumsShouldBeAllowed() {

        List<StopPlace.StopPlaceType> types = Arrays.asList(
                StopPlace.StopPlaceType.AIRPORT,
                StopPlace.StopPlaceType.ONSTREET_TRAM,
                StopPlace.StopPlaceType.ONSTREET_BUS
        );


        RoleAssignment roleAssignment = RoleAssignment.builder()
                .withRole("editStops")
                .withAdministrativeZone("01")
                .withOrganisation("OST")
                .withEntityClassification(ENTITY_TYPE, "StopPlace")
                .build();

        roleAssignment.getEntityClassifications().put("StopPlaceType", types.stream().map(Enum::toString).collect(toList()));


        StopPlace stopPlace = new StopPlace();

        types.forEach(type -> {
            stopPlace.stopPlaceType = type;
            boolean authorized = reflectionAuthorizationService.authorized(roleAssignment, stopPlace, roleAssignment.r);
            assertThat("Should have access to edit stop with type "+ type, authorized, is(true));
        });
    }

    @Test
    public void mixNegationForEnums() {
            RoleAssignment roleAssignment = RoleAssignment.builder()
                .withRole("editStops")
                .withAdministrativeZone("01")
                .withOrganisation("OST")
                .withEntityClassification(ENTITY_TYPE, "StopPlace")
                .withEntityClassification("StopPlaceType", StopPlace.StopPlaceType.AIRPORT.toString())
                .withEntityClassification("StopPlaceType", "!"+StopPlace.StopPlaceType.ONSTREET_BUS.toString())
                .withEntityClassification("StopPlaceType", StopPlace.StopPlaceType.ONSTREET_TRAM.toString())
                .build();


        StopPlace stopPlace = new StopPlace();

        stopPlace.stopPlaceType = StopPlace.StopPlaceType.AIRPORT;
        assertThat(reflectionAuthorizationService.authorized(roleAssignment, stopPlace, roleAssignment.r), is(true));


        stopPlace.stopPlaceType = StopPlace.StopPlaceType.ONSTREET_BUS;
        assertThat("no access for bus", reflectionAuthorizationService.authorized(roleAssignment, stopPlace, roleAssignment.r), is(false));


        stopPlace.stopPlaceType = StopPlace.StopPlaceType.ONSTREET_TRAM;
        assertThat(reflectionAuthorizationService.authorized(roleAssignment, stopPlace, roleAssignment.r), is(true));
    }



    @Test
    public void authorizedForCertainEnumValues() {

        for(StopPlace.StopPlaceType enumValue : StopPlace.StopPlaceType.values()){
            RoleAssignment roleAssignment = RoleAssignment.builder()
                    .withRole("editEnums")
                    .withAdministrativeZone("01")
                    .withOrganisation("OST")
                    .withEntityClassification(ENTITY_TYPE, "StopPlace")
                    .withEntityClassification("StopPlaceType", "!"+enumValue)
                    .build();

            StopPlace stopPlace = new StopPlace();
            stopPlace.stopPlaceType = enumValue;

            boolean authorized = reflectionAuthorizationService.authorized(roleAssignment, stopPlace, roleAssignment.r);
            assertThat("should not be authorized as negation is on !", authorized, is(false));

            Arrays.stream(StopPlace.StopPlaceType.values()).forEach(otherEnum -> {
                if(otherEnum != enumValue) {
                    stopPlace.stopPlaceType = otherEnum;
                    assertThat("One value is not allowed " + enumValue + ", but " + otherEnum + " is",
                            reflectionAuthorizationService.authorized(roleAssignment, stopPlace, roleAssignment.r), is(true));
                }
            });
        }
    }

    @Test
    public void authorizedWithSubmodeAndType() {
        RoleAssignment roleAssignment = RoleAssignment.builder()
                .withRole("editStops")
                .withOrganisation("OST")
                .withEntityClassification(ENTITY_TYPE, "StopPlace")
                .withEntityClassification("StopPlaceType", "!airport")
                .withEntityClassification("combinedfield", "!somevalue")
                .build();

        StopPlace stopPlace = new StopPlace();
        stopPlace.someField1 = null;
        stopPlace.someField2 = "somethingElse";

        fieldMappings.put("combinedfield", Arrays.asList("someField1", "someField2"));

        boolean authorized = reflectionAuthorizationService.authorized(roleAssignment, stopPlace, roleAssignment.r);
        assertThat(authorized, is(true));
    }

    private static class StopPlace {
        enum StopPlaceType {
            ONSTREET_BUS("onstreetBus"),
            ONSTREET_TRAM("onstreetTram"),
            AIRPORT("airport");
            private final String value;

            StopPlaceType(String v) {
                value = v;
            }
        }

        StopPlaceType stopPlaceType;
        String submode;

        String someField1;
        String someField2;

        @Override
        public String toString() {
            return MoreObjects.toStringHelper(this)
                    .add("stopPlaceType", stopPlaceType)
                    .add("submode", submode)
                    .add("someField1", someField1)
                    .add("someField2", someField2)
                    .toString();
        }
    }

}