/*
 * SPDX-License-Identifier: Apache-2.0
 */
package org.keycloak.amfa.rest.amfa;

import jakarta.ws.rs.Path;
import org.jboss.resteasy.reactive.NoCache;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

class AmfaResourceProviderTest {

    /**
     * The endpoints return realm settings and admin data, so a browser or proxy
     * must not cache them: a stale answer would show the admin page old values.
     */
    @Test
    void everyEndpointIsMarkedNoCache() {
        List<Method> endpoints = Arrays.stream(AmfaResourceProvider.class.getDeclaredMethods())
                .filter(m -> m.isAnnotationPresent(Path.class))
                .toList();
        assertFalse(endpoints.isEmpty());

        List<String> cacheable = endpoints.stream()
                .filter(m -> !m.isAnnotationPresent(NoCache.class))
                .map(Method::getName)
                .toList();
        assertEquals(List.of(), cacheable);
    }
}
