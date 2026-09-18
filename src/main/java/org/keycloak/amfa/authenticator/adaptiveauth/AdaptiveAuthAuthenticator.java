/*
 * SPDX-License-Identifier: Apache-2.0
 */
package org.keycloak.amfa.authenticator.adaptiveauth;

import org.keycloak.amfa.util.EventBuilderHelper;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.email.EmailException;
import org.keycloak.email.EmailTemplateProvider;
import org.keycloak.models.GroupModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.utils.StringUtil;
// UserAgent is parsed inline using a simple string-matching approach

import java.text.SimpleDateFormat;
import java.util.*;
import java.util.stream.Collectors;

import static org.keycloak.amfa.authenticator.authcontext.AuthContextAuthenticator.AUTH_CONTEXT_HASH;

@Slf4j
public class AdaptiveAuthAuthenticator implements Authenticator {
    public static final String RISK_LEVEL = "risk_level";
    public static final String USER_AGENT = "user_agent";
    public static final String SCREEN_RESOLUTION = "screen_resolution";
    public static final String LOCAL = "local";
    public static String AUTH_NOTE = "adaptive-auth-risk-level";
    /** "engine" or "fallback" -- see EventBuilderHelper.DECISION_SOURCE_DETAIL. */
    public static String DECISION_SOURCE_NOTE = "adaptive-auth-decision-source";

    protected final AdaptiveAuthUtils adaptiveAuthUtils;
    protected final KeycloakSession session;

    public AdaptiveAuthAuthenticator(AdaptiveAuthUtils adaptiveAuthUtils, KeycloakSession session) {
        this.adaptiveAuthUtils = adaptiveAuthUtils;
        this.session = session;
    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        UserModel user = context.getUser();
        if (user == null) {
            context.attempted();
            return;
        }

        // Generate a new UUID to ensure consistent tracking of the same event across webhook
        String eventId = UUID.randomUUID().toString();
        context.getAuthenticationSession().setAuthNote("eventId", eventId); // Store eventId as a note

        String ipAddress = context.getEvent().getEvent().getIpAddress();
        String userAgent = context.getHttpRequest().getHttpHeaders().getRequestHeaders().get("User-Agent").toString();
        String screenResolution = context.getAuthenticationSession().getUserSessionNotes().get("screenResolution");
        String locales = context.getHttpRequest().getHttpHeaders().getAcceptableLanguages()
                .stream().filter(locale -> !locale.getCountry().isEmpty())
                .map(Locale::toString).collect(Collectors.joining(",")).replace("_", "-");
        String realmName = context.getRealm().getName();
        String groupId = user.getGroupsStream().findFirst().map(GroupModel::getId).orElse("default");
        String authContexthash = context.getAuthenticationSession().getAuthNote(AUTH_CONTEXT_HASH);
        // A single labeled, sanitized line -- not one log.debug(value) call per
        // field. That old shape had two problems: values weren't labeled (only
        // position in a block of otherwise-identical-looking lines told them
        // apart), and screenResolution reached the log unsanitized, letting an
        // embedded CR/LF forge a fake log record. screenResolution is now
        // validated at capture (ScreenResolutionAuthenticator) so it can't
        // carry one, but this sanitizes defensively regardless, the same way
        // AuthContextAuthenticator's own log call does.
        //
        // userId/client/authContextHash are sanitized too, not just the
        // form/header-derived fields: Keycloak's own built-in
        // JBossLoggingEventListenerProvider sanitizes clientId and userId by
        // default for the same reason (a realm with anonymous Dynamic Client
        // Registration enabled lets a caller choose its own clientId, a JSON
        // body value, not a header), and authContextHash comes from the
        // engine's HTTP response, an external system whose output isn't
        // validated here. eventId is the one field left raw -- generated two
        // lines above via UUID.randomUUID(), never anything but
        // server-controlled.
        log.debug(
                "AdaptiveAuthAuthenticator: ipAddress={}, realm={}, userId={}, client={}, "
                        + "userAgent={}, locales={}, screenResolution={}, eventId={}, authContextHash={}",
                StringUtil.sanitizeSpacesAndQuotes(ipAddress, null),
                StringUtil.sanitizeSpacesAndQuotes(realmName, null),
                StringUtil.sanitizeSpacesAndQuotes(user.getId(), null),
                StringUtil.sanitizeSpacesAndQuotes(context.getAuthenticationSession().getClient().getClientId(), null),
                StringUtil.sanitizeSpacesAndQuotes(userAgent, null),
                StringUtil.sanitizeSpacesAndQuotes(locales, null),
                StringUtil.sanitizeSpacesAndQuotes(screenResolution, null),
                eventId,
                StringUtil.sanitizeSpacesAndQuotes(authContexthash, null));

        int defaultRiskLevel = AdaptiveAuthUtils.getFallbackRiskLevel(context.getRealm());

        AdaptiveAuthDecision decision;
        try {
            decision = adaptiveAuthUtils.getUserAdaptiveAuthDecision(
                    context.getSession(),
                    context.getAuthenticationSession(),
                    defaultRiskLevel,
                    user.getId(),
                    context.getAuthenticationSession().getClient().getClientId(),
                    ipAddress, userAgent, locales, screenResolution,
                    realmName, groupId, eventId, authContexthash);
        } catch (EngineUnavailableException e) {
            // adaptiveAuthFailureMode=mandatory: the engine could not be
            // consulted and the realm has explicitly opted out of proceeding at
            // any fallback level, so the login is denied outright rather than
            // silently downgraded.
            log.error("ADAPTIVE_AUTH_ENGINE_UNREACHABLE AdaptiveAuthAuthenticator: denying login "
                    + "(adaptiveAuthFailureMode=mandatory), engine could not be consulted: {}",
                    e.getMessage());
            context.getEvent().detail(EventBuilderHelper.DECISION_SOURCE_DETAIL, "engine_unreachable_denied");
            context.failure(AuthenticationFlowError.ACCESS_DENIED);
            return;
        }

        int riskLevel = decision.getRiskLevel();

        context.getAuthenticationSession().setAuthNote(USER_AGENT, userAgent);
        context.getAuthenticationSession().setAuthNote(SCREEN_RESOLUTION, screenResolution);
        context.getAuthenticationSession().setAuthNote(LOCAL, locales);
        context.getAuthenticationSession().setAuthNote(AUTH_NOTE, String.valueOf(riskLevel));
        context.getAuthenticationSession().setAuthNote(DECISION_SOURCE_NOTE,
                decision.isFromFallback() ? "fallback" : "engine");

        EventBuilderHelper.addExtraDetailsToEvent(context.getEvent(),context.getAuthenticationSession());

        boolean shouldSendEmailFlag = Boolean.parseBoolean(context.getRealm().getAttribute(AdaptiveAuthUtils.ADAPTIVE_AUTH_API_NOTIFY_ON_RISKY_LOGIN));

        if (shouldSendEmailFlag && riskLevel >= AdaptiveAuthUtils.HIGH_RISK_LEVEL) {
            log.debug("Sending email to user...");
            String[] osBrowser = parseUserAgent(userAgent);
            String os = osBrowser[0];
            String browser = osBrowser[1];
            String deviceDisplayName = StringUtils.trim((Objects.equals(browser, "Unknown") ? "" : browser) + " " + (Objects.equals(os, "Unknown") ? "" : os));
            if (deviceDisplayName.isEmpty()) {
                deviceDisplayName = "Unknown Device";
            }
            try {
                RealmModel realm = getRealm(session);
                Map<String, Object> emailBodyParams = new HashMap<>();
                emailBodyParams.put("deviceDisplayName", deviceDisplayName);
                emailBodyParams.put("realmName", realm.getDisplayName());
                emailBodyParams.put("email", user.getEmail());
                emailBodyParams.put("date", new SimpleDateFormat("EEE, MMM d, yyyy hh:mm:ss a z").format(new Date()));
                emailBodyParams.put("ipAddress", ipAddress);
                session.getProvider(EmailTemplateProvider.class)
                        .setRealm(realm)
                        .setUser(user)
                        .send("Login attempt", Collections.emptyList(), "adaptiveauth-login-notification.ftl", emailBodyParams);
            } catch (EmailException e) {
                log.error("authenticate -> Failed to send an notification email (" + e.getMessage() + ")");
            }
        }

        context.success();
    }

    static RealmModel getRealm(KeycloakSession session) {
        if (session.getContext() == null) {
            return null;
        }
        if (session.getContext().getRealm() != null) {
            return session.getContext().getRealm();
        }
        if (session.getContext().getAuthenticationSession() != null
                && session.getContext().getAuthenticationSession().getRealm() != null) {
            return session.getContext().getAuthenticationSession().getRealm();
        }
        if (session.getContext().getClient() != null
                && session.getContext().getClient().getRealm() != null) {
            return session.getContext().getClient().getRealm();
        }
        return null;
    }

    @Override
    public void action(AuthenticationFlowContext authenticationFlowContext) {

    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession keycloakSession, RealmModel realmModel, UserModel userModel) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession keycloakSession, RealmModel realmModel, UserModel userModel) {

    }

    @Override
    public void close() {

    }

    /**
     * Returns [osDisplayName, browserDisplayName] derived from the user-agent string.
     * Matches the OS and Browser enum names defined in AdaptiveAuthUtils.
     */
    private static String[] parseUserAgent(String userAgent) {
        if (userAgent == null) return new String[]{"Unknown", "Unknown"};
        String ua = userAgent.toLowerCase();

        String os;
        if (ua.contains("iphone") || ua.contains("ipad") || ua.contains("ipod")) {
            os = AdaptiveAuthUtils.OS.IOS.getName();
        } else if (ua.contains("mac os") || ua.contains("macintosh")) {
            os = AdaptiveAuthUtils.OS.MAC_OS.getName();
        } else if (ua.contains("android")) {
            os = AdaptiveAuthUtils.OS.DROID.getName();
        } else if (ua.contains("win64") || ua.contains("wow64")) {
            os = AdaptiveAuthUtils.OS.WIN64.getName();
        } else if (ua.contains("win32") || ua.contains("windows")) {
            os = AdaptiveAuthUtils.OS.WIN32.getName();
        } else if (ua.contains("linux")) {
            os = AdaptiveAuthUtils.OS.LINUX.getName();
        } else if (ua.contains("symbian")) {
            os = AdaptiveAuthUtils.OS.SYMBIAN.getName();
        } else if (ua.contains("blackberry")) {
            os = AdaptiveAuthUtils.OS.BLACKBERRY.getName();
        } else if (ua.contains("bot") || ua.contains("crawler") || ua.contains("spider")) {
            os = AdaptiveAuthUtils.OS.BOT.getName();
        } else {
            os = AdaptiveAuthUtils.OS.UNKNOWN.getName();
        }

        String browser;
        if (ua.contains("edg/") || ua.contains("edge/")) {
            browser = AdaptiveAuthUtils.Browser.EDGE.getName();
        } else if (ua.contains("opr/") || ua.contains("opera")) {
            browser = AdaptiveAuthUtils.Browser.OPERA.getName();
        } else if (ua.contains("firefox/")) {
            browser = AdaptiveAuthUtils.Browser.FIREFOX.getName();
        } else if (ua.contains("chrome/") || ua.contains("chromium/")) {
            browser = AdaptiveAuthUtils.Browser.CHROME.getName();
        } else if (ua.contains("safari/")) {
            browser = AdaptiveAuthUtils.Browser.SAFARI.getName();
        } else if (ua.contains("ucbrowser") || ua.contains("ucweb")) {
            browser = AdaptiveAuthUtils.Browser.UCWEB.getName();
        } else if (ua.contains("bot") || ua.contains("crawler")) {
            browser = AdaptiveAuthUtils.Browser.BOT.getName();
        } else {
            browser = AdaptiveAuthUtils.Browser.UNKNOWN.getName();
        }

        return new String[]{os, browser};
    }
}