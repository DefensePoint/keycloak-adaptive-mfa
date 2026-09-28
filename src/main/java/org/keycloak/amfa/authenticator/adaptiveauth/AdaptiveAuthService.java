/*
 * SPDX-License-Identifier: Apache-2.0
 */
package org.keycloak.amfa.authenticator.adaptiveauth;

import org.keycloak.amfa.authenticator.adaptiveauth.model.AdaptiveAuthResponse;
import lombok.extern.slf4j.Slf4j;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.models.KeycloakSession;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

@Slf4j
public class AdaptiveAuthService {

    /**
     * How long to wait on the risk engine before giving up and using the realm's
     * fallback level.
     *
     * <p>Without an explicit value SimpleHttp inherits Keycloak's default HTTP client
     * timeouts, which are effectively unbounded for this purpose: measured against an
     * engine address that drops packets, a login was held for 150 and 225 seconds in
     * two runs before falling back. The fallback was correct both times, but it
     * arrived long after the user, and any load balancer in front, had given up. Under
     * a network partition that is every login in the realm held for minutes, which is
     * an outage whatever the eventual answer.
     *
     * <p>Five seconds is chosen to be longer than any healthy call (a local engine
     * answers in tens of milliseconds) and shorter than a user's patience. Both the
     * connect and the read timeout are set: a refused connection fails immediately
     * anyway, but dropped packets hang at connect, and a wedged engine hangs at read.
     */
    private static final int ENGINE_TIMEOUT_MILLIS = 5000;

    private final KeycloakSession session;

    public AdaptiveAuthService(KeycloakSession session) {
        this.session = session;
    }

    public AdaptiveAuthResponse getAdaptiveAuthDecision(String token, String url, String userId, String clientId, String ipAddress, String userAgent, String locales, String screenResolution, String realmName, String groupId, String eventId, String authContextHash) throws IOException {
        log.debug("getAdaptiveAuthDecision: userId={}, clientId={}, ipAddress={}, userAgent={}, realmId={} ,group_id={},event_id={},authContextHash={}, url={}", userId, clientId, ipAddress, userAgent, realmName, groupId, eventId, authContextHash, url);
        Map<String, String> bodyParams = new HashMap<>();
        bodyParams.put("user_id", userId);
        bodyParams.put("client", clientId);
        bodyParams.put("ip_address", ipAddress);
        bodyParams.put("user_agent", userAgent);
        bodyParams.put("system_language", locales);
        bodyParams.put("screen_resolution", screenResolution);
        bodyParams.put("realm_id", realmName);
        bodyParams.put("group_id", groupId);
        bodyParams.put("event_id", eventId);
        bodyParams.put("auth_context_hash", authContextHash);

        SimpleHttp.Response httpResponse = SimpleHttp
                .doPost(url, session)
                .auth(token)
                .connectTimeoutMillis(ENGINE_TIMEOUT_MILLIS)
                .connectionRequestTimeoutMillis(ENGINE_TIMEOUT_MILLIS)
                .socketTimeOutMillis(ENGINE_TIMEOUT_MILLIS)
                .json(bodyParams)
                .asResponse();

        if (httpResponse.getStatus() >= 300) {
            log.error("getAdaptiveAuthDecision: httpResponse={}", httpResponse);
            throw new IOException(httpResponse.asString());
        }

        return httpResponse.asJson(AdaptiveAuthResponse.class);
    }
}
