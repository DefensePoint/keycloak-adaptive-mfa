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

import java.io.IOException;

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
    public static final int TOKEN_TIMEOUT_MILLIS = 5000;

    /**
     * Obtains a service account access token for the given client via client_credentials grant.
     * The client must have service accounts enabled in Keycloak.
     *
     * <p>Returns null when no token can be had, for any reason, and logs why. Callers
     * that tell an admin what went wrong use {@link #requestServiceAccountToken} instead.
     */
    public static String getServiceAccountToken(RealmModel realm, KeycloakSession session, String clientId) {
        try {
            return requestServiceAccountToken(realm, session, clientId);
        } catch (ServiceAccountNotConfiguredException e) {
            log.error(e.getMessage());
            return null;
        } catch (Exception e) {
            log.errorf(e, "Error obtaining service account token for client '%s'", clientId);
            return null;
        }
    }

    /**
     * Same as {@link #getServiceAccountToken}, but says why there is no token: a
     * {@link ServiceAccountNotConfiguredException} when the realm lacks the client or its
     * secret, an IOException when the token request fails or is refused.
     */
    public static String requestServiceAccountToken(RealmModel realm, KeycloakSession session, String clientId)
            throws IOException {
        ClientModel client = realm.getClientByClientId(clientId);
        if (client == null) {
            throw new ServiceAccountNotConfiguredException(
                    "client '" + clientId + "' not found in realm '" + realm.getName() + "'");
        }

        String clientSecret = client.getSecret();
        if (clientSecret == null || clientSecret.isEmpty()) {
            throw new ServiceAccountNotConfiguredException("client '" + clientId + "' has no secret");
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

        // "returned HTTP <status>" is how the admin page recognises a refusal, after
        // which it tells the admin that nothing was saved, which holds: the engine
        // was never called.
        if (response.getStatus() >= 300) {
            throw new IOException("the token endpoint returned HTTP " + response.getStatus()
                    + ": " + response.asString());
        }

        JsonNode tokenNode = response.asJson().get("access_token");
        if (tokenNode == null) {
            throw new IOException("the token response has no access_token");
        }
        return tokenNode.asText();
    }
}
