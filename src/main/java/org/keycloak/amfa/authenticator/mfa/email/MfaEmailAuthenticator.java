/*
 * SPDX-License-Identifier: Apache-2.0
 */
package org.keycloak.amfa.authenticator.mfa.email;

import org.jboss.logging.Logger;
import org.keycloak.amfa.authenticator.mfa.MfaUtils;
import org.keycloak.amfa.util.Constants;
import org.keycloak.amfa.util.EventBuilderHelper;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.authenticators.util.AuthenticatorUtils;
import org.keycloak.email.EmailException;
import org.keycloak.email.EmailTemplateProvider;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.sessions.AuthenticationSessionModel;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

public abstract class MfaEmailAuthenticator implements Authenticator {

    private static final Logger log = Logger.getLogger(MfaEmailAuthenticator.class);

    /**
     * How many wrong guesses a single issued code tolerates before it is
     * invalidated and a fresh one is issued. Deliberately small and not
     * realm-configurable: three attempts against a six-digit code is not a
     * search space worth widening, and the real backstop against sustained
     * guessing across many issued codes is the brute-force check below, not
     * this per-code number.
     */
    static final int MAX_ATTEMPTS_PER_CODE = 3;

    /**
     * How long an issued code stays valid, whether or not it is ever guessed
     * wrong. Keeps a code from a stale or abandoned attempt from still being
     * usable long after the login that requested it.
     */
    static final int CODE_TTL_SECONDS = 300;

    protected final MfaUtils mfaUtils;

    protected MfaEmailAuthenticator(MfaUtils mfaUtils) {
        this.mfaUtils = mfaUtils;
    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        if (denyIfLockedOut(context)) {
            return;
        }

        UserModel user = context.getUser();
        RealmModel realm = context.getRealm();
        KeycloakSession session = context.getSession();

        String code = mfaUtils.generateCode();
        mfaUtils.storeCode(context.getAuthenticationSession(), code);

        try {
            Map<String, Object> attrs = new HashMap<>();
            attrs.put("code", code);
            attrs.put("email", user.getEmail());
            session.getProvider(EmailTemplateProvider.class)
                    .setRealm(realm)
                    .setUser(user)
                    .setAuthenticationSession(context.getAuthenticationSession())
                    .send("mfaOTPSubject", Collections.emptyList(), "mfa-email-otp.ftl", attrs);
        } catch (EmailException e) {
            log.errorf(e, "Failed to send email OTP to user %s", user.getEmail());
        }

        challengeWithForm(context);
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        if (denyIfLockedOut(context)) {
            return;
        }

        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        AuthenticationSessionModel authSession = context.getAuthenticationSession();

        if (formData.containsKey("resend")) {
            // A fresh code, not a guess: resets this code's own attempt/TTL
            // budget, but NOT the brute-force counter below. An attacker
            // cannot dodge the account+address lockout by asking for a new
            // code instead of entering one -- every wrong guess against any
            // code this session ever issues still counts toward it.
            mfaUtils.clearCode(authSession);
            authenticate(context);
            return;
        }

        if (mfaUtils.isExpired(authSession, CODE_TTL_SECONDS)) {
            mfaUtils.clearCode(authSession);
            authenticate(context);
            return;
        }

        String enteredCode = formData.getFirst("code");
        if (mfaUtils.verifyCode(authSession, enteredCode)) {
            mfaUtils.clearCode(authSession);
            context.getProtector().successfulLogin(
                    context.getRealm(), context.getUser(), context.getConnection(), context.getUriInfo(),
                    authenticationCategory(context));
            // Keycloak builds a fresh EventBuilder per HTTP request rather than
            // reusing one across the whole login, so the risk_level/decision_source
            // details AdaptiveAuthAuthenticator attaches on the password step's
            // request are only present on the final LOGIN event when that step is
            // the only request in the flow -- they are absent whenever email/TOTP
            // step-up adds a later request, since that request's context.success()
            // fires the event that actually gets persisted. Re-attaching here, from
            // the auth-session notes that DO persist correctly across requests,
            // means whichever authenticator ends up last in the chain carries them
            // onto the event that actually gets persisted.
            EventBuilderHelper.addExtraDetailsToEvent(context.getEvent(), authSession);
            context.success();
            return;
        }

        // Wrong guess: counts against BOTH the per-code budget (this
        // challenge only) and the realm's brute-force protector (persistent
        // across a resend or a fresh challenge -- see the resend branch
        // above for why that persistence is the point).
        //
        // The two outcomes below need different handling here. Keycloak's own
        // flow engine (DefaultAuthenticationFlow.processResult) already calls
        // BruteForceProtector.failedLogin() itself, automatically, whenever an
        // authenticator's result is FAILED or FAILURE_CHALLENGE -- which is
        // exactly what the rejection branch below produces via
        // context.failureChallenge(). Calling the protector again there would
        // double-count every ordinary wrong guess. The reissue branch instead
        // calls authenticate(), which ends in context.challenge() (plain
        // CHALLENGE), a status the engine does NOT auto-log -- so that guess
        // needs an explicit call or it would silently go free, undermining
        // the "every wrong guess counts" guarantee the resend branch above
        // documents.
        int attempts = mfaUtils.incrementAttempts(authSession);

        if (attempts >= MAX_ATTEMPTS_PER_CODE) {
            context.getProtector().failedLogin(
                    context.getRealm(), context.getUser(), context.getConnection(), context.getUriInfo(),
                    authenticationCategory(context));
            mfaUtils.clearCode(authSession);
            authenticate(context);
            return;
        }

        LoginFormsProvider form = context.form()
                .setAttribute("email", context.getUser().getEmail())
                .setError("invalidOTPMessage");
        context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS,
                form.createForm("login-mfa-email.ftl"));
    }

    /**
     * The brute-force protector's per-category grouping key for this
     * execution. Resolved the same way Keycloak's own engine does it
     * ({@code AuthenticationProcessor.logFailure} passes
     * {@code execution.getAuthenticator()}, the provider id, not the
     * execution id): {@link AuthenticationManager#getAuthenticationCategory}
     * looks up that provider's {@code AuthenticatorFactory} and returns its
     * declared reference category, or {@code null} if it has none.
     */
    private String authenticationCategory(AuthenticationFlowContext context) {
        return AuthenticationManager.getAuthenticationCategory(
                context.getSession(), context.getExecution().getAuthenticator());
    }

    /**
     * Refuse outright -- before sending an email or showing the challenge --
     * if the realm's brute-force protector already has this account locked
     * out. Without this, a locked-out attacker could still keep requesting
     * fresh codes: {@code authenticate()} itself has no gate, and the
     * attempts-exhausted/expired/resend paths above all call back into it.
     *
     * <p>Blocks via {@code forceChallenge()}, not {@code failure()}. This
     * matters: Keycloak's flow engine auto-logs a brute-force failure for any
     * authenticator result of FAILED or FAILURE_CHALLENGE (the same
     * mechanism the wrong-guess handling in {@code action()} relies on and
     * deliberately avoids double-counting). {@code failure()} is a FAILED
     * result, so it would log ANOTHER failure every time this gate fires --
     * meaning every retry against an already-locked-out account would itself
     * extend or escalate the lockout. FORCE_CHALLENGE is not auto-logged;
     * it's the same idiom Keycloak's own
     * {@code AbstractUsernameFormAuthenticator.isDisabledByBruteForce()}
     * uses for this exact situation, confirmed by decompiling it. Reusing
     * {@link AuthenticatorUtils#getDisabledByBruteForceEventError} rather
     * than calling {@code isTemporarilyDisabled}/{@code isPermanentlyLockedOut}
     * directly keeps the temporary-vs-permanent distinction (and its event
     * error string) in sync with however Keycloak itself decides it.
     */
    private boolean denyIfLockedOut(AuthenticationFlowContext context) {
        UserModel user = context.getUser();
        String bruteForceError = AuthenticatorUtils.getDisabledByBruteForceEventError(context, user);
        if (bruteForceError == null) {
            return false;
        }
        context.getEvent().user(user).error(bruteForceError);
        String message = "user_temporarily_disabled".equals(bruteForceError)
                ? "accountTemporarilyDisabledMessage"
                : "accountPermanentlyDisabledMessage";
        Response challengeResponse = context.form()
                .setError(message)
                .createForm("login-mfa-email.ftl");
        context.forceChallenge(challengeResponse);
        return true;
    }

    private void challengeWithForm(AuthenticationFlowContext context) {
        LoginFormsProvider form = context.form()
                .setAttribute("email", context.getUser().getEmail());
        Response challenge = form.createForm("login-mfa-email.ftl");
        context.challenge(challenge);
    }

    @Override
    public boolean requiresUser() {
        return true;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    /**
     * Gate on the realm opting in to step-up enrolment.
     *
     * <p>The flow engine requires both this and {@code isUserSetupAllowed()} before it
     * will offer the required action from {@link #setRequiredActions}. Returning false
     * leaves the previous outcome, a denied login, which is the safe default: Keycloak
     * defers a required action until after authentication, so enrolling here would let
     * the very login that triggered the step-up through without a second factor.
     *
     * @see org.keycloak.amfa.util.Constants#ALLOW_STEP_UP_ENROLMENT
     */
    @Override
    public boolean areRequiredActionsEnabled(KeycloakSession session, RealmModel realm) {
        return Boolean.parseBoolean(realm.getAttribute(Constants.ALLOW_STEP_UP_ENROLMENT));
    }

    /**
     * Give the user a way to supply the missing email address.
     *
     * <p>Reached only when {@code configuredFor} returned false, which for this
     * factor means the account has no email address to send a code to. Without a
     * required action here the flow engine has nowhere to go and throws
     * {@code CREDENTIAL_SETUP_REQUIRED}, which the browser shows as an opaque error
     * and Keycloak records as {@code invalid_user_credentials} even though the
     * password was accepted.
     *
     * <p>{@code UPDATE_PROFILE} is the action that can fix it, since the address
     * lives on the profile rather than in a credential. This mirrors what the TOTP
     * factor does with {@code CONFIGURE_TOTP}: both factors let the user complete
     * the missing setup mid-login instead of dead-ending.
     */
    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
        log.infof("User %s has no email address for the email second factor; "
                + "requesting UPDATE_PROFILE so they can supply one", user.getId());
        user.addRequiredAction(UserModel.RequiredAction.UPDATE_PROFILE);
    }

    @Override
    public void close() {
    }
}
