/*
 * SPDX-License-Identifier: Apache-2.0
 */
package org.keycloak.amfa.authenticator.screenresolution;

import jakarta.ws.rs.core.Response;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.authenticators.browser.UsernamePasswordForm;

import java.util.regex.Pattern;

/**
 * Captures the browser's screen resolution into the {@code screenResolution}
 * user-session note, which the Auth Context and Adaptive Authentication steps
 * read and forward to the engine as a risk signal.
 *
 * <p>It renders a tiny page ({@code screen-resolution.ftl}) whose JavaScript
 * (theme {@code scripts=js/index.js}) fills a hidden {@code screenRes} field
 * with {@code screen.width x screen.height} and auto-submits it back here.
 */
@Slf4j
public class ScreenResolutionAuthenticator extends UsernamePasswordForm {

    public static final String SCREEN_RESOLUTION_FORM = "screen-resolution.ftl";
    public static final String SCREEN_RESOLUTION_NOTE = "screenResolution";
    public static final String SCREEN_RES_PARAM = "screenRes";

    /**
     * A real submission is always {@code <width>x<height>}. Enforcing that
     * shape here -- the single place this value ever enters the system --
     * means a value that isn't a screen resolution (in particular, one
     * carrying an embedded CR/LF to forge a fake log/event record) is never
     * stored, so nothing downstream (the auth-context log, the adaptive-auth
     * debug log, the Keycloak event details) can be reached by it at all.
     * Mirrors the engine-side SCREEN_RESOLUTION_REGEX in the AMFA engine repo
     * for the same signal.
     */
    private static final Pattern SCREEN_RESOLUTION_PATTERN = Pattern.compile("\\d{1,5}[xX]\\d{1,5}");

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        Response response = context.form().createForm(SCREEN_RESOLUTION_FORM);
        context.challenge(response);
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        try {
            String screenResolution = context.getHttpRequest().getDecodedFormParameters().getFirst(SCREEN_RES_PARAM);
            if (!StringUtils.isBlank(screenResolution)
                    && SCREEN_RESOLUTION_PATTERN.matcher(screenResolution).matches()) {
                context.getAuthenticationSession().setUserSessionNote(SCREEN_RESOLUTION_NOTE, screenResolution);
                context.success();
            } else {
                // Blank or malformed (including a value carrying an embedded
                // CR/LF to forge a fake log/event record). Re-challenge with
                // the same capture page rather than leaving this action's
                // flow status unset: an unset status is what a real submission
                // never produces, and it crashes Keycloak's own
                // DefaultAuthenticationFlow.processResult() with an NPE
                // (FlowStatus.ordinal() on a null status) instead of cleanly
                // re-prompting.
                context.challenge(context.form().createForm(SCREEN_RESOLUTION_FORM));
            }
        } catch (Exception e) {
            // Swallowing this exception without touching the flow status would
            // leave it unset -- the same shape the else-branch above guards
            // against, just reachable via a different trigger (e.g.
            // getDecodedFormParameters() or form().createForm() itself
            // throwing) instead of a malformed screenRes value. Deliberately
            // calling the simplest possible status-setter here rather than
            // repeating the challenge/render call that may be what threw in
            // the first place.
            log.error("Error processing form action", e);
            context.failure(AuthenticationFlowError.INTERNAL_ERROR);
        }
    }

}
