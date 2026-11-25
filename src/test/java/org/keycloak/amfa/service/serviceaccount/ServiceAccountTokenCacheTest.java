/*
 * SPDX-License-Identifier: Apache-2.0
 */
package org.keycloak.amfa.service.serviceaccount;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * A login used to fetch a fresh service account token from Keycloak twice, over
 * HTTP, and every admin page call once more. On a busy Keycloak that extra token
 * work made the overload worse. The token is now reused until shortly before it
 * expires.
 */
class ServiceAccountTokenCacheTest {

    private static final long SECOND = 1_000_000_000L;

    /** A clock the test moves by hand. */
    private static final class Clock {
        long now = 1_000 * SECOND;

        long read() {
            return now;
        }

        void advanceSeconds(long seconds) {
            now += seconds * SECOND;
        }
    }

    /** Hands out t1, t2, ... and counts the requests. */
    private static class Endpoint implements ServiceAccountTokenCache.Fetcher {
        final AtomicInteger requests = new AtomicInteger();
        long expiresInSeconds = 300;
        IOException failure;

        @Override
        public ServiceAccountTokenCache.Fetched fetch() throws IOException {
            int n = requests.incrementAndGet();
            if (failure != null) {
                throw failure;
            }
            return new ServiceAccountTokenCache.Fetched("t" + n, expiresInSeconds);
        }
    }

    private final Clock clock = new Clock();
    private final ServiceAccountTokenCache cache = new ServiceAccountTokenCache(clock::read);
    private static final ServiceAccountTokenCache.Key KEY =
            new ServiceAccountTokenCache.Key("realm-id", "adaptive-auth-api", "https://iam.test/realms/demo/protocol/openid-connect/token", "secret");

    @Test
    void aTokenIsReusedUntilShortlyBeforeItExpires() throws Exception {
        Endpoint endpoint = new Endpoint();

        assertEquals("t1", cache.get(KEY, endpoint));
        clock.advanceSeconds(200);
        assertEquals("t1", cache.get(KEY, endpoint));
        clock.advanceSeconds(69); // 269 s into a 300 s token
        assertEquals("t1", cache.get(KEY, endpoint));

        assertEquals(1, endpoint.requests.get());
    }

    @Test
    void aTokenCloseToExpiryIsReplaced() throws Exception {
        Endpoint endpoint = new Endpoint();
        cache.get(KEY, endpoint);

        clock.advanceSeconds(271); // within 30 s of a 300 s token's expiry

        assertEquals("t2", cache.get(KEY, endpoint));
        assertEquals("t2", cache.get(KEY, endpoint));
        assertEquals(2, endpoint.requests.get());
    }

    @Test
    void anExpiredTokenIsNeverHandedOut() throws Exception {
        Endpoint endpoint = new Endpoint();
        cache.get(KEY, endpoint);
        clock.advanceSeconds(301);
        endpoint.failure = new IOException("token endpoint down");

        assertThrows(IOException.class, () -> cache.get(KEY, endpoint));
    }

    @Test
    void aFailedRefreshKeepsServingTheStillValidToken() throws Exception {
        Endpoint endpoint = new Endpoint();
        cache.get(KEY, endpoint);
        clock.advanceSeconds(280);
        endpoint.failure = new IOException("token endpoint slow");

        assertEquals("t1", cache.get(KEY, endpoint));
        // The next login tries again rather than waiting for expiry.
        endpoint.failure = null;
        assertEquals("t3", cache.get(KEY, endpoint));
    }

    @Test
    void aTokenWithoutAKnownLifetimeIsNotKept() throws Exception {
        Endpoint endpoint = new Endpoint();
        endpoint.expiresInSeconds = 0; // expires_in missing from the response

        cache.get(KEY, endpoint);
        cache.get(KEY, endpoint);

        assertEquals(2, endpoint.requests.get());
    }

    @Test
    void aVeryShortLivedTokenIsStillReusedForHalfItsLife() throws Exception {
        Endpoint endpoint = new Endpoint();
        endpoint.expiresInSeconds = 20;

        cache.get(KEY, endpoint);
        clock.advanceSeconds(9);
        cache.get(KEY, endpoint);
        clock.advanceSeconds(2); // 11 s into a 20 s token
        cache.get(KEY, endpoint);

        assertEquals(2, endpoint.requests.get());
    }

    @Test
    void anythingTheTokenDependsOnGetsItsOwnToken() throws Exception {
        Endpoint endpoint = new Endpoint();
        cache.get(KEY, endpoint);

        cache.get(new ServiceAccountTokenCache.Key("other-realm", KEY.clientId(), KEY.tokenEndpoint(), "secret"), endpoint);
        cache.get(new ServiceAccountTokenCache.Key(KEY.realmId(), "other-client", KEY.tokenEndpoint(), "secret"), endpoint);
        // The address the user signed in at sets the token's issuer.
        cache.get(new ServiceAccountTokenCache.Key(KEY.realmId(), KEY.clientId(), "https://other.test/realms/demo/protocol/openid-connect/token", "secret"), endpoint);
        // A rotated client secret must not keep the token the old one got.
        cache.get(new ServiceAccountTokenCache.Key(KEY.realmId(), KEY.clientId(), KEY.tokenEndpoint(), "rotated"), endpoint);

        assertEquals(5, endpoint.requests.get());
    }

    @Test
    void aTokenTheEngineRejectedIsForgotten() throws Exception {
        Endpoint endpoint = new Endpoint();
        String token = cache.get(KEY, endpoint);

        cache.forget(token);

        assertEquals("t2", cache.get(KEY, endpoint));
    }

    @Test
    void forgettingAnotherTokenKeepsTheCachedOne() throws Exception {
        Endpoint endpoint = new Endpoint();
        cache.get(KEY, endpoint);

        cache.forget("not-the-cached-token");
        cache.forget(null);

        assertEquals("t1", cache.get(KEY, endpoint));
        assertEquals(1, endpoint.requests.get());
    }

    @Test
    void expiredTokensDoNotPileUp() throws Exception {
        // The token endpoint is built from the address the user signed in at, so a
        // Keycloak without a fixed hostname can see many. Their tokens must not stay
        // in memory after they expire.
        Endpoint endpoint = new Endpoint();
        for (int i = 0; i < 50; i++) {
            cache.get(new ServiceAccountTokenCache.Key(KEY.realmId(), KEY.clientId(), "https://host-" + i + ".test/token", "secret"), endpoint);
        }
        assertEquals(50, cache.size());

        clock.advanceSeconds(301);
        cache.get(KEY, endpoint);

        assertEquals(1, cache.size());
    }

    @Test
    void theSecretIsNotKeptInTheKey() {
        assertTrue(!KEY.toString().contains("secret"), KEY.toString());
    }

    @Test
    void manyLoginsNearExpiryTriggerOneRefresh() throws Exception {
        Endpoint slow = new Endpoint() {
            @Override
            public ServiceAccountTokenCache.Fetched fetch() throws IOException {
                ServiceAccountTokenCache.Fetched fetched = super.fetch();
                try {
                    Thread.sleep(200);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
                return fetched;
            }
        };
        cache.get(KEY, slow);
        clock.advanceSeconds(280);

        ExecutorService pool = Executors.newFixedThreadPool(32);
        CountDownLatch start = new CountDownLatch(1);
        List<Future<String>> logins = new ArrayList<>();
        for (int i = 0; i < 64; i++) {
            logins.add(pool.submit(() -> {
                start.await();
                return cache.get(KEY, slow);
            }));
        }
        start.countDown();
        for (Future<String> login : logins) {
            String token = login.get(10, TimeUnit.SECONDS);
            assertTrue(token.equals("t1") || token.equals("t2"), token);
        }
        pool.shutdown();

        assertEquals(2, slow.requests.get(), "one fetch at first, one refresh near expiry");
    }
}
