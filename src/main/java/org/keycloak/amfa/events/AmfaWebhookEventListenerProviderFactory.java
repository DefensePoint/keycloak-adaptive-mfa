/*
 * SPDX-License-Identifier: Apache-2.0
 */
package org.keycloak.amfa.events;

import org.keycloak.Config;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventListenerProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

/**
 * Registers the AMFA webhook event listener. Enable it per realm under
 * Realm settings → Events → Event listeners (provider id {@code amfa-webhook}).
 */
public class AmfaWebhookEventListenerProviderFactory implements EventListenerProviderFactory {

    public static final String PROVIDER_ID = "amfa-webhook";

    /**
     * Lanes the webhooks are sent on, each sending one at a time. They carry
     * as many webhooks a second as there are lanes divided by the engine's
     * answer time: thousands from a healthy engine, and still 32 a second from
     * one that takes a second per webhook. Idle lanes cost a parked thread each.
     */
    private static final int SENDER_LANES = 32;

    /**
     * Webhooks each lane holds while the engine is slow or down. A webhook's
     * token expires 30 seconds after the login, so a deeper queue would only
     * hold webhooks the engine refuses anyway.
     */
    private static final int SENDER_QUEUE_PER_LANE = 250;

    /** How long the waiting webhooks get to go out when Keycloak shuts down. */
    private static final long SENDER_SHUTDOWN_WAIT_MILLIS = 5000;

    private AmfaWebhookSender sender;

    @Override
    public EventListenerProvider create(KeycloakSession session) {
        return new AmfaWebhookEventListenerProvider(session, sender);
    }

    @Override
    public void init(Config.Scope config) {
        sender = new AmfaWebhookSender(SENDER_LANES, SENDER_QUEUE_PER_LANE);
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
    }

    @Override
    public void close() {
        if (sender != null) {
            sender.close(SENDER_SHUTDOWN_WAIT_MILLIS);
        }
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}
