/*
 * SPDX-License-Identifier: Apache-2.0
 */
package org.keycloak.amfa.util;

import org.apache.http.client.config.RequestConfig;
import org.keycloak.connections.httpclient.HttpClientProvider;
import org.keycloak.http.simple.SimpleHttp;
import org.keycloak.models.KeycloakSession;

/**
 * Creates the {@link SimpleHttp} clients for the calls that must not wait on the
 * engine longer than a set time.
 */
public class AmfaHttp {

    /** A client whose connect, connection request and read timeouts are all {@code timeoutMillis}. */
    public static SimpleHttp create(KeycloakSession session, int timeoutMillis) {
        return withTimeout(SimpleHttp.create(session), timeoutMillis);
    }

    /**
     * Like {@link #create(KeycloakSession, int)}, but still usable after the
     * session has closed, for a request sent from another thread. It uses
     * Keycloak's shared HTTP client, which lives as long as the server.
     */
    public static SimpleHttp createDetached(KeycloakSession session, int timeoutMillis) {
        HttpClientProvider provider = session.getProvider(HttpClientProvider.class);
        return withTimeout(SimpleHttp.create(provider.getHttpClient())
                .withMaxConsumedResponseSize(provider.getMaxConsumedResponseSize()), timeoutMillis);
    }

    private static SimpleHttp withTimeout(SimpleHttp http, int timeoutMillis) {
        return http.withRequestConfig(RequestConfig.custom()
                .setConnectTimeout(timeoutMillis)
                .setConnectionRequestTimeout(timeoutMillis)
                .setSocketTimeout(timeoutMillis)
                .build());
    }

    private AmfaHttp() {}
}
