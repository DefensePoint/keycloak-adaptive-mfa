/*
 * SPDX-License-Identifier: Apache-2.0
 */
package org.keycloak.amfa.rest.amfa;

import org.keycloak.amfa.service.AmfaApiService;
import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resource.RealmResourceProviderFactory;

public class AmfaResourceProviderFactory implements RealmResourceProviderFactory {

    public static final String ID = "amfa-api";

    @Override
    public RealmResourceProvider create(KeycloakSession keycloakSession) {
        AmfaApiService apiService = new AmfaApiService(keycloakSession);

        return new AmfaResourceProvider(keycloakSession,apiService);
    }

    @Override
    public void init(Config.Scope scope) {}

    @Override
    public void postInit(KeycloakSessionFactory keycloakSessionFactory) {}

    @Override
    public void close() {}

    @Override
    public String getId() {
        return ID;
    }
}
