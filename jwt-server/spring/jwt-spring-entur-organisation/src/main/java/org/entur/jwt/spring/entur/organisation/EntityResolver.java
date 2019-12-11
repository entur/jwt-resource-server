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

public interface EntityResolver {
    /**
     * If entity itself cannot be checked for authorization, but the owning entity
     * can. For instance, if a Quay belongs to StopPlace, the Quay cannot be
     * checked, but the StopPlace can.
     *
     * @param entity child entity
     * @return the parent entity to check for authorization
     */
    Object resolveCorrectEntity(Object entity);
}
