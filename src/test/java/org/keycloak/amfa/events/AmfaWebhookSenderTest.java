/*
 * SPDX-License-Identifier: Apache-2.0
 */
package org.keycloak.amfa.events;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
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

    @Test
    void oneUsersWebhooksGoOutInTheOrderTheyCame() {
        sender = new AmfaWebhookSender(4, 1000, 1000);
        List<Integer> sent = Collections.synchronizedList(new ArrayList<>());

        for (int i = 0; i < 500; i++) {
            int n = i;
            assertTrue(sender.submit("user-1", () -> sent.add(n)));
        }
        sender.close(5000);

        assertEquals(IntStream.range(0, 500).boxed().collect(Collectors.toList()), sent);
    }

    @Test
    void manyUsersQueuedFromManyThreadsGoOutInOrderOneAtATime() throws Exception {
        int users = 200;
        int perUser = 50;
        sender = new AmfaWebhookSender(8, perUser, users * perUser);
        Map<String, List<Integer>> sent = new ConcurrentHashMap<>();
        Map<String, AtomicInteger> sending = new ConcurrentHashMap<>();
        AtomicInteger overlaps = new AtomicInteger();
        AtomicInteger refused = new AtomicInteger();
        CountDownLatch done = new CountDownLatch(users * perUser);

        // Each producer queues a share of the users, every user's webhooks in order.
        ExecutorService producers = Executors.newFixedThreadPool(16);
        for (int p = 0; p < 16; p++) {
            int producer = p;
            producers.execute(() -> {
                for (int n = 0; n < perUser; n++) {
                    for (int u = producer; u < users; u += 16) {
                        String user = "user-" + u;
                        int seq = n;
                        boolean queued = sender.submit(user, () -> {
                            if (sending.computeIfAbsent(user, k -> new AtomicInteger()).incrementAndGet() > 1) {
                                overlaps.incrementAndGet();
                            }
                            sent.computeIfAbsent(user, k -> Collections.synchronizedList(new ArrayList<>())).add(seq);
                            Thread.yield();
                            sending.get(user).decrementAndGet();
                            done.countDown();
                        });
                        if (!queued) {
                            refused.incrementAndGet();
                        }
                    }
                }
            });
        }
        producers.shutdown();

        assertTrue(done.await(30, TimeUnit.SECONDS), "every webhook should go out");
        assertEquals(0, refused.get());
        assertEquals(0, overlaps.get(), "a user's webhooks must never be sent at the same time");
        assertEquals(users, sent.size());
        List<Integer> inOrder = IntStream.range(0, perUser).boxed().collect(Collectors.toList());
        for (Map.Entry<String, List<Integer>> e : sent.entrySet()) {
            assertEquals(inOrder, List.copyOf(e.getValue()), e.getKey() + " went out of order");
        }
    }

    @Test
    void aBusyUserDoesNotHoldUpAnotherUser() throws Exception {
        sender = new AmfaWebhookSender(2, 10, 100);
        String busyUser = "user-1";
        String otherUser = "user-2";
        CountDownLatch busyStarted = new CountDownLatch(1);
        CountDownLatch otherSent = new CountDownLatch(1);

        sender.submit(busyUser, blocked(busyStarted));
        assertTrue(busyStarted.await(5, TimeUnit.SECONDS));
        sender.submit(busyUser, () -> { });
        sender.submit(otherUser, otherSent::countDown);

        assertTrue(otherSent.await(5, TimeUnit.SECONDS), "the other user's webhook waited for the busy user's");
    }

    @Test
    void usersWithWebhooksWaitingTakeTurns() throws Exception {
        sender = new AmfaWebhookSender(1, 10, 100);
        CountDownLatch started = new CountDownLatch(1);
        List<String> sent = Collections.synchronizedList(new ArrayList<>());
        CountDownLatch allSent = new CountDownLatch(4);
        sender.submit("user-0", blocked(started));
        assertTrue(started.await(5, TimeUnit.SECONDS));
        for (int i = 0; i < 3; i++) {
            sender.submit("user-1", () -> { sent.add("user-1"); allSent.countDown(); });
        }
        sender.submit("user-2", () -> { sent.add("user-2"); allSent.countDown(); });

        release.countDown();

        assertTrue(allSent.await(5, TimeUnit.SECONDS));
        assertEquals(List.of("user-1", "user-2", "user-1", "user-1"), sent);
    }

    @Test
    void aFullQueueDropsTheWebhookInsteadOfWaiting() throws Exception {
        sender = new AmfaWebhookSender(1, 2, 100);
        CountDownLatch started = new CountDownLatch(1);
        sender.submit("user-1", blocked(started));
        assertTrue(started.await(5, TimeUnit.SECONDS));

        assertTrue(sender.submit("user-1", () -> { }));
        assertTrue(sender.submit("user-1", () -> { }));
        long before = System.nanoTime();
        boolean queued = sender.submit("user-1", () -> { });

        assertFalse(queued);
        assertTrue(TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - before) < 1000, "submit waited for room");
        assertTrue(sender.submit("user-2", () -> { }), "another user's queue has room");
    }

    @Test
    void webhooksBeyondTheTotalAreDroppedWhateverTheUser() throws Exception {
        sender = new AmfaWebhookSender(1, 10, 3);
        CountDownLatch started = new CountDownLatch(1);
        sender.submit("user-0", blocked(started));
        assertTrue(started.await(5, TimeUnit.SECONDS));

        assertTrue(sender.submit("user-1", () -> { }));
        assertTrue(sender.submit("user-2", () -> { }));
        assertTrue(sender.submit("user-3", () -> { }));

        assertFalse(sender.submit("user-4", () -> { }));
    }

    @Test
    void aFailingWebhookDoesNotStopTheUsersQueue() throws Exception {
        sender = new AmfaWebhookSender(1, 10, 10);
        CountDownLatch next = new CountDownLatch(1);

        sender.submit("user-1", () -> { throw new IllegalStateException("boom"); });
        sender.submit("user-1", next::countDown);

        assertTrue(next.await(5, TimeUnit.SECONDS));
    }

    @Test
    void closingLetsTheWaitingWebhooksGoOutAndTakesNoMore() {
        sender = new AmfaWebhookSender(2, 100, 100);
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
