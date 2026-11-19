/*
 * SPDX-License-Identifier: Apache-2.0
 */
package org.keycloak.amfa.authenticator.mfa.email;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.amfa.authenticator.adaptiveauth.AdaptiveAuthAuthenticator;
import org.keycloak.amfa.authenticator.mfa.MfaUtils;
import org.keycloak.amfa.util.EventBuilderHelper;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.common.util.Time;
import org.keycloak.email.EmailException;
import org.keycloak.email.EmailTemplateProvider;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.http.HttpRequest;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.services.managers.BruteForceProtector;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.Response;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * How many codes one login gets, and when: a refresh shows the live code
 * again, and a new code is sent only on Resend, on expiry or after the third
 * wrong guess, each within the step's limit.
 */
@ExtendWith(MockitoExtension.class)
class MfaEmailAuthenticatorTest {

    @Mock private AuthenticationFlowContext context;
    @Mock private KeycloakSession session;
    @Mock private RealmModel realm;
    @Mock private UserModel user;
    @Mock private AuthenticationSessionModel authSession;
    @Mock private EmailTemplateProvider email;
    @Mock private LoginFormsProvider form;
    @Mock private EventBuilder event;
    @Mock private HttpRequest request;
    @Mock private BruteForceProtector protector;
    @Mock private AuthenticationExecutionModel execution;
    @Mock private Response codePage;
    @Mock private Response errorPage;

    private MfaEmailAuthenticator authenticator;
    private final Map<String, String> notes = new HashMap<>();
    /** The code each sent email carried, in order. */
    private final List<String> sentCodes = new ArrayList<>();
    private boolean emailFails;

    @BeforeEach
    void setUp() throws EmailException {
        authenticator = new MfaEmailAuthenticator(new MfaUtils()) {
            @Override
            public boolean configuredFor(KeycloakSession s, RealmModel r, UserModel u) {
                return true;
            }
        };
        lenient().doAnswer(inv -> notes.put(inv.getArgument(0), inv.getArgument(1)))
                .when(authSession).setAuthNote(anyString(), anyString());
        lenient().doAnswer(inv -> notes.get(inv.<String>getArgument(0)))
                .when(authSession).getAuthNote(anyString());
        lenient().doAnswer(inv -> notes.remove(inv.<String>getArgument(0)))
                .when(authSession).removeAuthNote(anyString());

        lenient().when(context.getSession()).thenReturn(session);
        lenient().when(context.getRealm()).thenReturn(realm);
        lenient().when(context.getUser()).thenReturn(user);
        lenient().when(context.getAuthenticationSession()).thenReturn(authSession);
        lenient().when(context.form()).thenReturn(form);
        lenient().when(context.getEvent()).thenReturn(event);
        lenient().when(context.getHttpRequest()).thenReturn(request);
        lenient().when(context.getProtector()).thenReturn(protector);
        lenient().when(context.getExecution()).thenReturn(execution);
        lenient().when(event.user(any(UserModel.class))).thenReturn(event);
        lenient().when(event.detail(anyString(), nullable(String.class))).thenReturn(event);
        notes.put(AdaptiveAuthAuthenticator.AUTH_NOTE, "3");
        notes.put(AdaptiveAuthAuthenticator.EVENT_ID_NOTE, "decision-1");
        lenient().when(user.getEmail()).thenReturn("user@example.com");
        lenient().when(form.setAttribute(anyString(), any())).thenReturn(form);
        lenient().when(form.setError(anyString())).thenReturn(form);
        lenient().when(form.createForm("login-mfa-email.ftl")).thenReturn(codePage);
        lenient().when(form.createErrorPage(any())).thenReturn(errorPage);

        lenient().when(session.getProvider(EmailTemplateProvider.class)).thenReturn(email);
        lenient().when(email.setRealm(any())).thenReturn(email);
        lenient().when(email.setUser(any())).thenReturn(email);
        lenient().when(email.setAuthenticationSession(any())).thenReturn(email);
        lenient().doAnswer(inv -> {
            if (emailFails) {
                throw new EmailException("SMTP down");
            }
            Map<String, Object> attrs = inv.getArgument(3);
            sentCodes.add((String) attrs.get("code"));
            return null;
        }).when(email).send(anyString(), anyList(), anyString(), anyMap());
    }

    private void limit(String value) {
        AuthenticatorConfigModel config = new AuthenticatorConfigModel();
        config.setConfig(new HashMap<>(Map.of(MfaEmailAuthenticator.CONFIG_CODES_PER_LOGIN, value)));
        when(context.getAuthenticatorConfig()).thenReturn(config);
    }

    private void post(String field, String value) {
        MultivaluedHashMap<String, String> params = new MultivaluedHashMap<>();
        params.add(field, value);
        when(request.getDecodedFormParameters()).thenReturn(params);
        authenticator.action(context);
    }

    private void resend() {
        post("resend", "");
    }

    private void guess(String code) {
        post("code", code);
    }

    private String wrong() {
        String live = notes.get(MfaUtils.AUTH_NOTE_OTP_CODE);
        return live.equals("000000") ? "000001" : "000000";
    }

    private void expireLiveCode() {
        notes.put(MfaUtils.AUTH_NOTE_OTP_ISSUED_AT,
                Long.toString(Time.currentTime() - MfaEmailAuthenticator.CODE_TTL_SECONDS - 1));
    }

    private void verifyLimitPage(int times) {
        verify(form, times(times)).setError("mfaCodeLimitReached");
        verify(context, times(times)).challenge(errorPage);
    }

    /** Resend at the limit with a live code: the code page again, saying no more can be sent. */
    private void verifyNoMoreCodes(int times) {
        verify(form, times(times)).setError("mfaNoMoreCodes");
        verify(context, never()).challenge(errorPage);
    }

    /** All three codes sent and the last one expired: nothing is left to enter. */
    private void reachTheLimitPage() {
        sendAllThreeCodes();
        expireLiveCode();
        authenticator.authenticate(context);
        verifyLimitPage(1);
    }

    @Test
    void theFirstShowingSendsOneCode() {
        authenticator.authenticate(context);

        assertEquals(1, sentCodes.size());
        verify(context).challenge(codePage);
    }

    @Test
    void aRefreshShowsTheLiveCodeAgainAndSendsNothing() {
        authenticator.authenticate(context);
        String live = notes.get(MfaUtils.AUTH_NOTE_OTP_CODE);

        authenticator.authenticate(context);
        authenticator.authenticate(context);

        assertEquals(1, sentCodes.size());
        assertEquals(live, notes.get(MfaUtils.AUTH_NOTE_OTP_CODE));
        verify(context, times(3)).challenge(codePage);
    }

    /** The first code and every Resend up to the default limit of three. */
    private void sendAllThreeCodes() {
        authenticator.authenticate(context);
        resend();
        resend();
        assertEquals(3, sentCodes.size());
    }

    @Test
    void resendSendsANewCodeUpToTheDefaultLimitOfThree() {
        authenticator.authenticate(context);
        resend();
        assertEquals(2, sentCodes.size());
        assertEquals(sentCodes.get(1), notes.get(MfaUtils.AUTH_NOTE_OTP_CODE));

        resend();
        assertEquals(3, sentCodes.size());
        assertEquals(sentCodes.get(2), notes.get(MfaUtils.AUTH_NOTE_OTP_CODE));

        resend();

        assertEquals(3, sentCodes.size());
        verifyNoMoreCodes(1);
        assertEquals(sentCodes.get(2), notes.get(MfaUtils.AUTH_NOTE_OTP_CODE));
    }

    // Resend at the limit used to clear the code before finding the limit, so a
    // code still valid in the user's inbox could no longer be used.
    @Test
    void resendAtTheLimitKeepsTheLiveCodeAndItStillLogsIn() {
        sendAllThreeCodes();
        String live = sentCodes.get(2);

        resend();

        assertEquals(3, sentCodes.size());
        assertEquals(live, notes.get(MfaUtils.AUTH_NOTE_OTP_CODE));
        verifyNoMoreCodes(1);
        verify(event, never()).error(MfaEmailAuthenticator.CODE_LIMIT_REACHED);
        verify(context, never()).failureChallenge(any(), any());

        guess(live);
        verify(context).success();
    }

    // Each showing of the limit page used to record a LOGIN_ERROR, which the
    // engine counts among the user's failed logins: reloading the page could
    // raise the user's risk for later logins.
    @Test
    void theLimitIsRecordedOnceHoweverOftenItsPageIsShown() {
        reachTheLimitPage();

        authenticator.authenticate(context);
        authenticator.authenticate(context);
        resend();
        guess("123456");

        verifyLimitPage(5);
        verify(event, times(1)).error(MfaEmailAuthenticator.CODE_LIMIT_REACHED);
    }

    @Test
    void theLimitPageIsNotCountedAsAFailedLogin() {
        reachTheLimitPage();

        verify(context, never()).failureChallenge(any(), any());
        verify(context, never()).failure(any(), any());
        verify(protector, never()).failedLogin(any(), any(), any(), any(), any());
    }

    @Test
    void afterTheLimitARefreshShowsTheLimitPageAgainAndSendsNothing() {
        reachTheLimitPage();
        authenticator.authenticate(context);

        assertEquals(3, sentCodes.size());
        verifyLimitPage(2);
    }

    @Test
    void anExpiredCodeIsReplacedOnRefreshWithinTheLimit() {
        authenticator.authenticate(context);
        expireLiveCode();
        authenticator.authenticate(context);

        assertEquals(2, sentCodes.size());
        assertEquals(sentCodes.get(1), notes.get(MfaUtils.AUTH_NOTE_OTP_CODE));
    }

    @Test
    void anExpiredCodeAtTheLimitShowsTheLimitPage() {
        sendAllThreeCodes();
        expireLiveCode();
        authenticator.authenticate(context);

        assertEquals(3, sentCodes.size());
        verifyLimitPage(1);
    }

    @Test
    void theThirdWrongGuessSendsANewCodeWithinTheLimitAndCountsAsAFailure() {
        authenticator.authenticate(context);
        for (int i = 0; i < 3; i++) {
            guess(wrong());
        }

        assertEquals(2, sentCodes.size());
        verify(context, times(2)).failureChallenge(eq(AuthenticationFlowError.INVALID_CREDENTIALS), eq(codePage));
        verify(protector).failedLogin(any(), any(), any(), any(), any());
    }

    @Test
    void theThirdWrongGuessAtTheLimitShowsTheLimitPage() {
        sendAllThreeCodes();
        for (int i = 0; i < 3; i++) {
            guess(wrong());
        }

        assertEquals(3, sentCodes.size());
        verify(protector).failedLogin(any(), any(), any(), any(), any());
        verifyLimitPage(1);
    }

    @Test
    void theRightCodeLogsIn() {
        authenticator.authenticate(context);
        guess(sentCodes.get(0));

        verify(context).success();
    }

    @Test
    void aCodeEnteredAfterTheLimitIsNotCheckedOrCounted() {
        sendAllThreeCodes();
        String last = sentCodes.get(2);
        expireLiveCode();
        authenticator.authenticate(context);
        guess(last);

        verify(context, never()).success();
        verify(protector, never()).failedLogin(any(), any(), any(), any(), any());
        verifyLimitPage(2);
    }

    @Test
    void theStepsSettingRaisesTheLimit() {
        limit("4");
        sendAllThreeCodes();
        resend();
        assertEquals(4, sentCodes.size());

        resend();
        assertEquals(4, sentCodes.size());
        verifyNoMoreCodes(1);
    }

    @Test
    void theStepsSettingLowersTheLimit() {
        limit("1");
        authenticator.authenticate(context);
        resend();

        assertEquals(1, sentCodes.size());
        verifyNoMoreCodes(1);
    }

    @Test
    void anUnusableSettingFallsBackToThree() {
        for (String value : new String[]{"", "abc", "0", "-1"}) {
            reset(context);
            setUpAgain();
            limit(value);
            authenticator.authenticate(context);
            resend();
            resend();
            resend();
            assertEquals(3, sentCodes.size(), "setting '" + value + "'");
        }
    }

    @Test
    void aFailedSendIsNotCountedAndTheNextShowingTriesAgain() {
        emailFails = true;
        authenticator.authenticate(context);
        assertTrue(sentCodes.isEmpty());
        assertNull(notes.get(MfaUtils.AUTH_NOTE_OTP_CODE));

        emailFails = false;
        authenticator.authenticate(context);
        resend();

        assertEquals(2, sentCodes.size());
    }

    /** A fresh login for a loop iteration: new notes, nothing sent. */
    private void setUpAgain() {
        notes.clear();
        sentCodes.clear();
        try {
            setUp();
        } catch (EmailException e) {
            throw new AssertionError(e);
        }
    }

    /** The event of a failed attempt carries the login's AMFA details. */
    private void verifyAmfaDetails(int times) {
        verify(event, times(times)).detail(AdaptiveAuthAuthenticator.RISK_LEVEL, "3");
        verify(event, times(times)).detail(EventBuilderHelper.AMFA_EVENT_ID_DETAIL, "decision-1");
    }

    @Test
    void aWrongCodeIsRecordedWithTheAmfaDetailsBeforeItIsCounted() {
        authenticator.authenticate(context);
        guess(wrong());

        verifyAmfaDetails(1);
        InOrder order = inOrder(event, context);
        order.verify(event).user(user);
        order.verify(event).error(MfaEmailAuthenticator.WRONG_CODE);
        order.verify(context).failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, codePage);
    }

    @Test
    void everyWrongGuessIsRecordedIncludingTheThirdThatSendsANewCode() {
        authenticator.authenticate(context);
        for (int i = 0; i < 3; i++) {
            guess(wrong());
        }

        verify(event, times(3)).error(MfaEmailAuthenticator.WRONG_CODE);
        verifyAmfaDetails(3);
        InOrder order = inOrder(event, protector);
        order.verify(event, times(3)).error(MfaEmailAuthenticator.WRONG_CODE);
        order.verify(protector).failedLogin(any(), any(), any(), any(), any());
    }

    @Test
    void theLimitEventCarriesTheAmfaDetails() {
        reachTheLimitPage();

        verify(event).error(MfaEmailAuthenticator.CODE_LIMIT_REACHED);
        verifyAmfaDetails(1);
    }

    @Test
    void aLockoutRefusalCarriesTheAmfaDetails() {
        when(realm.isBruteForceProtected()).thenReturn(true);
        when(protector.isTemporarilyDisabled(session, realm, user)).thenReturn(true);

        authenticator.authenticate(context);

        verify(event).error(Errors.USER_TEMPORARILY_DISABLED);
        verifyAmfaDetails(1);
        assertTrue(sentCodes.isEmpty());
    }

    @Test
    void theRightCodeRecordsNoError() {
        authenticator.authenticate(context);
        guess(sentCodes.get(0));

        verify(event, never()).error(anyString());
    }

    /*
     * The code page comes after the password and before the second factor, so
     * whoever has only the password sees it. It names the mailbox without
     * giving the address away.
     */

    @Test
    void theCodePageShowsTheAddressMasked() {
        authenticator.authenticate(context);

        verify(form).setAttribute("email", "use*@example.com");
        verify(form, never()).setAttribute("email", "user@example.com");
    }

    @Test
    void theCodePageAfterAWrongCodeShowsTheAddressMasked() {
        authenticator.authenticate(context);
        guess(wrong());

        verify(form, times(2)).setAttribute("email", "use*@example.com");
        verify(form, never()).setAttribute("email", "user@example.com");
    }
}
