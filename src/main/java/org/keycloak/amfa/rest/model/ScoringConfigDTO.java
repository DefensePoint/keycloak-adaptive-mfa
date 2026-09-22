/*
 * SPDX-License-Identifier: Apache-2.0
 */
package org.keycloak.amfa.rest.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.*;

import java.util.List;

/**
 * Per-realm risk-scoring configuration forwarded to the AMFA engine's
 * /{realm}/scoring endpoint. Unset fields fall back to engine env defaults.
 */
@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
@ToString
@JsonIgnoreProperties(ignoreUnknown = true)
public class ScoringConfigDTO {
    private String mode;
    private Double bias;
    private List<Double> thresholds;
}
