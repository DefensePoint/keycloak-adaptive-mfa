/*
 * SPDX-License-Identifier: Apache-2.0
 */
package org.keycloak.amfa.events;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AmfaWebhookSenderTest {

    private AmfaWebhookSender sender;
    private final CountDownLatch release = new CountDownLatch(1);

    @AfterEach
    void tearDown() {
        release.countDown();
        sender.close(5000);
    }

    private Runnable blocked(CountDownLatch started) {
        return () -> {
            started.countDown();
            try {
                release.await(10, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        };
    }

    private static int lane(String key, int lanes) {
        return Math.floorMod(key.hashCode(), lanes);
    }

    @Test
    void oneUsersWebhooksGoOutInTheOrderTheyCame() {
        sender = new AmfaWebhookSender(4, 1000);
        List<Integer> sent = Collections.synchronizedList(new ArrayList<>());

        for (int i = 0; i < 500; i++) {
            int n = i;
            assertTrue(sender.submit("user-1", () -> sent.add(n)));
        }
        sender.close(5000);

        assertEquals(IntStream.range(0, 500).boxed().collect(Collectors.toList()), sent);
    }

    @Test
    void aSlowWebhookDoesNotHoldUpAnotherUsers() throws Exception {
        sender = new AmfaWebhookSender(4, 10);
        String slowUser = "user-1";
        String otherUser = IntStream.range(2, 100).mapToObj(i -> "user-" + i)
                .filter(key -> lane(key, 4) != lane(slowUser, 4)).findFirst().orElseThrow();
        assertNotEquals(lane(slowUser, 4), lane(otherUser, 4));
        CountDownLatch slowStarted = new CountDownLatch(1);
        CountDownLatch otherSent = new CountDownLatch(1);

        sender.submit(slowUser, blocked(slowStarted));
        assertTrue(slowStarted.await(5, TimeUnit.SECONDS));
        sender.submit(otherUser, otherSent::countDown);

        assertTrue(otherSent.await(5, TimeUnit.SECONDS), "the other user's webhook waited for the slow one");
    }

    @Test
    void aFullLaneDropsTheWebhookInsteadOfWaiting() throws Exception {
        sender = new AmfaWebhookSender(1, 2);
        CountDownLatch started = new CountDownLatch(1);
        sender.submit("user-1", blocked(started));
        assertTrue(started.await(5, TimeUnit.SECONDS));

        assertTrue(sender.submit("user-1", () -> { }));
        assertTrue(sender.submit("user-1", () -> { }));
        long before = System.nanoTime();
        boolean queued = sender.submit("user-1", () -> { });

        assertFalse(queued);
        assertTrue(TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - before) < 1000, "submit waited for room");
    }

    @Test
    void aFailingWebhookDoesNotStopItsLane() throws Exception {
        sender = new AmfaWebhookSender(1, 10);
        CountDownLatch next = new CountDownLatch(1);

        sender.submit("user-1", () -> { throw new IllegalStateException("boom"); });
        sender.submit("user-1", next::countDown);

        assertTrue(next.await(5, TimeUnit.SECONDS));
    }

    @Test
    void closingLetsTheWaitingWebhooksGoOutAndTakesNoMore() {
        sender = new AmfaWebhookSender(2, 100);
        List<Integer> sent = Collections.synchronizedList(new ArrayList<>());
        for (int i = 0; i < 50; i++) {
            int n = i;
            sender.submit("user-" + (i % 7), () -> sent.add(n));
        }

        sender.close(5000);

        assertEquals(50, sent.size());
        assertFalse(sender.submit("user-1", () -> sent.add(-1)));
        assertEquals(50, sent.size());
    }
}
