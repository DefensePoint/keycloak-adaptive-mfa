/*
 * SPDX-License-Identifier: Apache-2.0
 */
package org.keycloak.amfa.rest.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.*;

import java.util.List;

@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
@ToString
@JsonIgnoreProperties(ignoreUnknown = true)
public class AdaptiveAuthConfig {
    private List<AdaptiveAuthConfigParameter> parameters;
    private Object extraParameter;
}