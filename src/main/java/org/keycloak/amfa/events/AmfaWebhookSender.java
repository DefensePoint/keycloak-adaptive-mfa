/*
 * SPDX-License-Identifier: Apache-2.0
 */
package org.keycloak.amfa.events;

import lombok.extern.slf4j.Slf4j;

import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

/**
 * Sends login webhooks off the login thread, so a slow or unreachable engine
 * cannot hold up a login.
 *
 * <p>Each webhook runs on one of a fixed set of single-thread lanes, picked by
 * the user the event is about. One user's events therefore reach the engine in
 * the order Keycloak emitted them, for example a wrong code's LOGIN_ERROR
 * before the LOGIN that follows the right one, while different users' events
 * are sent in parallel.
 *
 * <p>Each lane holds a bounded number of waiting webhooks. When the engine
 * cannot keep up and a lane is full, the webhook is dropped with a warning
 * rather than queued without limit.
 */
@Slf4j
public class AmfaWebhookSender {

    private final ThreadPoolExecutor[] lanes;

    public AmfaWebhookSender(int laneCount, int queuePerLane) {
        lanes = new ThreadPoolExecutor[laneCount];
        for (int i = 0; i < laneCount; i++) {
            String name = "amfa-webhook-" + (i + 1);
            lanes[i] = new ThreadPoolExecutor(1, 1, 0L, TimeUnit.MILLISECONDS,
                    new LinkedBlockingQueue<>(queuePerLane),
                    task -> {
                        Thread thread = new Thread(task, name);
                        thread.setDaemon(true);
                        return thread;
                    },
                    new ThreadPoolExecutor.AbortPolicy());
        }
    }

    /**
     * Queue a webhook on the lane for {@code key}. Returns false when that lane
     * is full or the sender has been closed, in which case the webhook is not sent.
     */
    public boolean submit(String key, Runnable webhook) {
        ThreadPoolExecutor lane = lanes[Math.floorMod(key == null ? 0 : key.hashCode(), lanes.length)];
        try {
            lane.execute(() -> {
                try {
                    webhook.run();
                } catch (RuntimeException e) {
                    log.warn("AMFA webhook delivery failed: {}", e.getMessage());
                }
            });
            return true;
        } catch (RejectedExecutionException e) {
            return false;
        }
    }

    /** Stop taking webhooks, and give the waiting ones up to {@code waitMillis} to go out. */
    public void close(long waitMillis) {
        for (ThreadPoolExecutor lane : lanes) {
            lane.shutdown();
        }
        long deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(waitMillis);
        try {
            for (ThreadPoolExecutor lane : lanes) {
                long left = deadline - System.nanoTime();
                if (left <= 0 || !lane.awaitTermination(left, TimeUnit.NANOSECONDS)) {
                    lane.shutdownNow();
                }
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            for (ThreadPoolExecutor lane : lanes) {
                lane.shutdownNow();
            }
        }
    }
}
