/*
 * SPDX-License-Identifier: Apache-2.0
 */
package org.keycloak.amfa.util;

import org.apache.http.client.config.RequestConfig;
import org.keycloak.http.simple.SimpleHttp;
import org.keycloak.models.KeycloakSession;

/**
 * Creates the {@link SimpleHttp} clients for the calls that must not wait on the
 * engine longer than a set time.
 */
public class AmfaHttp {

    /** A client whose connect, connection request and read timeouts are all {@code timeoutMillis}. */
    public static SimpleHttp create(KeycloakSession session, int timeoutMillis) {
        return SimpleHttp.create(session).withRequestConfig(RequestConfig.custom()
                .setConnectTimeout(timeoutMillis)
                .setConnectionRequestTimeout(timeoutMillis)
                .setSocketTimeout(timeoutMillis)
                .build());
    }

    private AmfaHttp() {}
}
