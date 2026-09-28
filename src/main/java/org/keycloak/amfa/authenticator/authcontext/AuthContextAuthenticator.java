/*
 * SPDX-License-Identifier: Apache-2.0
 */
package org.keycloak.amfa.authenticator.authcontext;


import org.keycloak.amfa.authenticator.adaptiveauth.AdaptiveAuthUtils;
import org.keycloak.amfa.authenticator.authcontext.model.AuthContextModel;
import org.keycloak.amfa.service.serviceaccount.ServiceAccountService;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.apache.http.HttpStatus;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.utils.StringUtil;

import java.io.IOException;
import java.net.URISyntaxException;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.stream.Collectors;

@Slf4j
public class AuthContextAuthenticator implements Authenticator {

    /** Milliseconds to wait on the engine before falling back. See sendHttpPost. */
    private static final int ENGINE_TIMEOUT_MILLIS = 5000;
    private static final String URL = "auth_context";
    public static final String ADAPTIVE_AUTH_API = "adaptive-auth-api";
    public static final String AUTH_CONTEXT_HASH = "authContextHash";
    public static final String CONTEXT_VALUE = "contextValue";
    public static final String SCREEN_RESOLUTION = "screen_resolution";
    public static final String CLIENT = "client";

    private final KeycloakSession session;
    private final ObjectMapper mapper = new ObjectMapper();

    public AuthContextAuthenticator(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        try {
            String ipAddress = context.getEvent().getEvent().getIpAddress();
            String userAgent = context.getHttpRequest().getHttpHeaders().getRequestHeaders().get("User-Agent").toString();
            // Captured earlier in the flow by the Screen Resolution authenticator
            // (login-page JS -> "screenResolution" user-session note).
            String screenResolution = context.getAuthenticationSession().getUserSessionNotes().get("screenResolution");
            String locales = context.getHttpRequest().getHttpHeaders().getAcceptableLanguages()
                    .stream().filter(locale -> !locale.getCountry().isEmpty())
                    .map(Locale::toString).collect(Collectors.joining(",")).replace("_", "-");
            String client = context.getAuthenticationSession().getClient().getClientId();

            String token = getTokenFromServiceAccount();

            String endpoint = StringUtils.defaultString(context.getSession().getContext().getRealm().getAttribute(AdaptiveAuthUtils.ADAPTIVE_AUTH_ENDPOINT));
            String url = endpoint.concat("/").concat(URL);

            AuthContextModel authContextMap = new AuthContextModel(client, ipAddress, userAgent, locales, screenResolution);
            // screenResolution is validated at capture (ScreenResolutionAuthenticator)
            // so it can't carry a CR/LF, but this line-breaks on a whole model's
            // worth of fields at once, so sanitize defensively -- the same call
            // Keycloak's own built-in event-to-log listener makes for this exact
            // reason (see org.keycloak.events.log.JBossLoggingEventListenerProvider).
            log.info("AuthContextModel {}", StringUtil.sanitizeSpacesAndQuotes(authContextMap.toString(), null));

            SimpleHttp.Response httpResponse = sendHttpPost(url, token, authContextMap, context.getSession());
            if (httpResponse != null && httpResponse.getStatus() == HttpStatus.SC_OK) {
                String responseBody = httpResponse.asString();
                JsonNode jsonNode = mapper.readTree(responseBody);
                String hash = jsonNode.path("hash").asText();

                Map<String, String> contextValueAndHash = new HashMap<>();
                contextValueAndHash.put(AUTH_CONTEXT_HASH, hash);
                contextValueAndHash.put(SCREEN_RESOLUTION, screenResolution);
                contextValueAndHash.put(CLIENT, client);

                int lifespanSeconds = 3600; //1 hour

                context.getSession().singleUseObjects().put(CONTEXT_VALUE, lifespanSeconds, contextValueAndHash);
                context.getAuthenticationSession().setAuthNote(AUTH_CONTEXT_HASH, hash);
                // Adversarial review finding: hash comes straight out of the
                // engine's HTTP response, an external system whose output
                // isn't validated here -- sanitize it too, for the same
                // reason as the AuthContextModel log line above.
                log.info("Auth context hash from AMFA: {}", StringUtil.sanitizeSpacesAndQuotes(hash, null));
            } else {
                log.warn("Failed to get valid response from AMFA: HTTP status {}", httpResponse != null ? httpResponse.getStatus() : "null");
            }
            context.success();
        } catch (Exception e) {
            // Fail open: an engine outage must not block login. Adaptive
            // Authentication downstream falls back to the realm's fallbackRisk
            // (or denies, if that realm has opted into adaptiveAuthFailureMode
            // =mandatory -- this earlier context-gathering step is not itself a
            // risk decision, so it stays fail-open regardless; the enforcement
            // point is AdaptiveAuthAuthenticator). Leaving the flow without a
            // status here would NPE the login.
            //
            // "ADAPTIVE_AUTH_ENGINE_UNREACHABLE" is a stable, greppable marker
            // (see AdaptiveAuthUtils.handleEngineFailure) so a log shipper/alert
            // rule can catch either engine-call failure independent of the
            // surrounding message text.
            log.error("ADAPTIVE_AUTH_ENGINE_UNREACHABLE Authentication context evaluation failed: {}", e.getMessage(), e);
            context.success();
        }
    }

    @Override
    public void action(AuthenticationFlowContext context) {

    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return false;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {

    }

    @Override
    public void close() {

    }

    private String getTokenFromServiceAccount() throws URISyntaxException, IOException {
        return ServiceAccountService.getServiceAccountToken(session.getContext().getRealm(), session, ADAPTIVE_AUTH_API);
    }

    /**
     * Post the authentication context to the engine, bounded by a timeout.
     *
     * <p>Same limit and same reasoning as {@code AdaptiveAuthService}: without one,
     * SimpleHttp inherits Keycloak's default client timeouts and an engine that drops
     * packets holds the login for minutes. This call matters as much as the decision
     * call, because it runs first in the flow, so an unbounded wait here is added to
     * an unbounded wait there.
     */
    private SimpleHttp.Response sendHttpPost(String url, String token, AuthContextModel model, KeycloakSession session) throws IOException {
        return SimpleHttp.doPost(url, session)
                .auth(token)
                .connectTimeoutMillis(ENGINE_TIMEOUT_MILLIS)
                .connectionRequestTimeoutMillis(ENGINE_TIMEOUT_MILLIS)
                .socketTimeOutMillis(ENGINE_TIMEOUT_MILLIS)
                .json(model)
                .asResponse();
    }
}
