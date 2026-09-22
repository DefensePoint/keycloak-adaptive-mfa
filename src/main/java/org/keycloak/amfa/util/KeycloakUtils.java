/*
 * SPDX-License-Identifier: Apache-2.0
 */
package org.keycloak.amfa.util;

import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.RealmModel;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

public class KeycloakUtils {

    public static IdentityProviderModel getIdp(RealmModel realm, String username) {
        String domain = EmailUtils.getEmailDomain(username);

        Optional<IdentityProviderModel> idp = realm.getIdentityProvidersStream()
                .filter(IdentityProviderModel::isEnabled)
                .filter(identityProvider -> checkDomainInIdentityProviders(domain, identityProvider))
                .findFirst();

        return idp.orElse(null);
    }

    private static boolean checkDomainInIdentityProviders(String domain, IdentityProviderModel identityProvider) {
        if(identityProvider.getConfig().get("domainMapping") != null) {
            String domainMapping = identityProvider.getConfig().get("domainMapping");
            Set<String> domains = new HashSet<>(Arrays.asList(domainMapping.replaceAll("\\s+", "").split("\\s*,\\s*")));
            return domains.contains(domain);
        }
        return false;
    }

    private KeycloakUtils() {}
}
