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

    /** Tokens reused across logins on this node until shortly before they expire. */
    private static final ServiceAccountTokenCache TOKENS = new ServiceAccountTokenCache(System::nanoTime);

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
        // Checked on every call, not only when a token is fetched: a cached token
        // must stop being used as soon as its client, or the client's service
        // account, is switched off, as it did when every call fetched a new one.
        if (!client.isEnabled()) {
            throw new ServiceAccountNotConfiguredException("client '" + clientId + "' is disabled");
        }
        if (!client.isServiceAccountsEnabled()) {
            throw new ServiceAccountNotConfiguredException("client '" + clientId + "' has service accounts disabled");
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

        ServiceAccountTokenCache.Key key =
                new ServiceAccountTokenCache.Key(realm.getId(), clientId, tokenEndpoint, clientSecret);
        return TOKENS.get(key, () -> fetchToken(session, tokenEndpoint, clientId, clientSecret));
    }

    /**
     * Forgets a token the engine rejected, so the next call asks Keycloak for a
     * fresh one instead of reusing it until it expires.
     */
    public static void forgetToken(String token) {
        TOKENS.forget(token);
    }

    /**
     * Whether an engine answer may mean it refused the token. The engine answers
     * 403 for a token it cannot verify (a signing key it no longer finds after a
     * key rotation, an untrusted issuer) and 401 for a missing one. Dropping a
     * token on a 403 that was about something else costs one token request.
     */
    public static boolean rejectsToken(int status) {
        return status == 401 || status == 403;
    }

    private static ServiceAccountTokenCache.Fetched fetchToken(KeycloakSession session, String tokenEndpoint,
            String clientId, String clientSecret) throws IOException {
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

        JsonNode body = response.asJson();
        JsonNode tokenNode = body.get("access_token");
        if (tokenNode == null) {
            throw new IOException("the token response has no access_token");
        }
        // 0 when Keycloak does not say: such a token is used once, not kept.
        JsonNode expiresIn = body.get("expires_in");
        return new ServiceAccountTokenCache.Fetched(tokenNode.asText(),
                expiresIn != null && expiresIn.canConvertToLong() ? expiresIn.asLong() : 0);
    }
}
