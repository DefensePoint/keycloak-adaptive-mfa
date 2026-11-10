/*
 * SPDX-License-Identifier: Apache-2.0
 */
package org.keycloak.amfa.service.serviceaccount;

import com.fasterxml.jackson.databind.JsonNode;
import org.jboss.logging.Logger;
import org.keycloak.amfa.util.AmfaHttp;
import org.keycloak.http.simple.SimpleHttpResponse;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;

public class ServiceAccountService {
    private static final Logger log = Logger.getLogger(ServiceAccountService.class);

    /**
     * How long to wait on Keycloak's own token endpoint. The token is fetched
     * before every engine call, at login and on the admin pages, so this wait
     * comes on top of the engine's own timeout.
     *
     * <p>Keycloak's default HTTP client sets no connect timeout and no limit on
     * waiting for a pooled connection, only a 5 second read timeout. The token
     * endpoint is reached at the address the user signed in with, which can be a
     * load balancer or a public name that does not resolve back to Keycloak from
     * inside the cluster; if that address drops packets, every login waits on the
     * operating system's connect timeout, a minute or more, before falling back.
     * Five seconds is far longer than a healthy token request takes, and matches
     * the engine calls at login.
     */
    static final int TOKEN_TIMEOUT_MILLIS = 5000;

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

            SimpleHttpResponse response = AmfaHttp.create(session, TOKEN_TIMEOUT_MILLIS)
                    .doPost(tokenEndpoint)
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
