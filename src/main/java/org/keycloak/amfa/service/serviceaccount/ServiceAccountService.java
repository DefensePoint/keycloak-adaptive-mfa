/*
 * SPDX-License-Identifier: Apache-2.0
 */
package org.keycloak.amfa.service.serviceaccount;

import com.fasterxml.jackson.databind.JsonNode;
import org.jboss.logging.Logger;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;

public class ServiceAccountService {
    private static final Logger log = Logger.getLogger(ServiceAccountService.class);

    /**
     * Obtains a service account access token for the given client via client_credentials grant.
     * The client must have service accounts enabled in Keycloak.
     */
    public static String getServiceAccountToken(RealmModel realm, KeycloakSession session, String clientId) {
        try {
            ClientModel client = realm.getClientByClientId(clientId);
            if (client == null) {
                log.errorf("Client not found: %s", clientId);
                return null;
            }

            String clientSecret = client.getSecret();
            if (clientSecret == null || clientSecret.isEmpty()) {
                log.errorf("Client '%s' has no secret configured", clientId);
                return null;
            }

            // Build the token endpoint URL using the Keycloak base URI. The base
            // URI has no trailing slash when the realm sets a frontendUrl, so
            // normalize instead of assuming one.
            String baseUri = session.getContext().getUri().getBaseUri().toString();
            if (!baseUri.endsWith("/")) {
                baseUri = baseUri + "/";
            }
            String tokenEndpoint = baseUri + "realms/" + realm.getName()
                    + "/protocol/openid-connect/token";

            SimpleHttp.Response response = SimpleHttp.doPost(tokenEndpoint, session)
                    .param("grant_type", "client_credentials")
                    .param("client_id", clientId)
                    .param("client_secret", clientSecret)
                    .asResponse();

            if (response.getStatus() >= 300) {
                log.errorf("Failed to get service account token for client '%s': HTTP %d — %s",
                        clientId, response.getStatus(), response.asString());
                return null;
            }

            JsonNode json = response.asJson();
            JsonNode tokenNode = json.get("access_token");
            if (tokenNode == null) {
                log.error("Token response missing access_token field");
                return null;
            }
            return tokenNode.asText();

        } catch (Exception e) {
            log.errorf(e, "Error obtaining service account token for client '%s'", clientId);
            return null;
        }
    }
}
