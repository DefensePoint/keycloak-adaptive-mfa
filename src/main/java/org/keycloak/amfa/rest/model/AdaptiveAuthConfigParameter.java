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
public class AdaptiveAuthConfigParameter {
    private String realm_id;
    private String parameter_name;
    private boolean disabled;
    private int weight;
    private String group_id;
    private List<String> whitelist;
    private List<String> blacklist;
    // Realm-level dormancy threshold for the inactive_account signal. Boxed
    // Integer, not int, so an absent value stays null and the engine applies its
    // own default rather than receiving a spurious 0. snake_case to match the
    // engine's JSON, like group_id above.
    private Integer inactive_days;
}