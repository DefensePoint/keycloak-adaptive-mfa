/*
 * SPDX-License-Identifier: Apache-2.0
 */
package org.keycloak.amfa.rest.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.*;

@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
@ToString
@JsonIgnoreProperties(ignoreUnknown = true)
public class Country {
    private String name;
    private String code;
}
