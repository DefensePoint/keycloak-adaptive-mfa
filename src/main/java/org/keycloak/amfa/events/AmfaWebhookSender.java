/*
 * SPDX-License-Identifier: Apache-2.0
 */
package org.keycloak.amfa.events;

import lombok.extern.slf4j.Slf4j;

import java.util.ArrayDeque;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Sends login webhooks off the login thread, so a slow or unreachable engine
 * cannot hold up a login.
 *
 * <p>Each user the events are about has a queue of their own, and only one of
 * a user's webhooks is sent at a time. One user's events therefore reach the
 * engine in the order Keycloak emitted them, for example a wrong code's
 * LOGIN_ERROR before the LOGIN that follows the right one, while different
 * users' events are sent in parallel on a shared set of threads. A user with
 * many webhooks waiting, as in a password-guessing run on one account, holds
 * at most one thread: after each webhook the user goes to the back of the
 * line, so other users are never stuck behind them.
 *
 * <p>A user can have a bounded number of webhooks waiting, and all users
 * together another. When the engine cannot keep up and either is reached, the
 * webhook is dropped with a warning rather than queued without limit.
 */
@Slf4j
public class AmfaWebhookSender {

    private final ThreadPoolExecutor threads;
    private final int queuePerUser;
    private final int queueTotal;

    // The users with webhooks waiting or being sent. A user is on the threads'
    // queue, or running on a thread, exactly while they are in this map.
    private final Map<String, ArrayDeque<Runnable>> queues = new HashMap<>();
    private int waiting;
    private final AtomicInteger threadNumber = new AtomicInteger();
    // Set once a close stops waiting: the webhooks still waiting are dropped.
    private volatile boolean stopped;

    public AmfaWebhookSender(int threadCount, int queuePerUser, int queueTotal) {
        this.threads = new ThreadPoolExecutor(threadCount, threadCount, 0L, TimeUnit.MILLISECONDS,
                new LinkedBlockingQueue<>(),
                task -> {
                    Thread thread = new Thread(task, "amfa-webhook-" + threadNumber.incrementAndGet());
                    thread.setDaemon(true);
                    return thread;
                });
        this.queuePerUser = queuePerUser;
        this.queueTotal = queueTotal;
    }

    /**
     * Queue a webhook for the user {@code key}. Returns false when that user's
     * queue or all queues together are full, or the sender has been closed, in
     * which case the webhook is not sent.
     */
    public boolean submit(String key, Runnable webhook) {
        String user = key == null ? "" : key;
        boolean first;
        synchronized (this) {
            ArrayDeque<Runnable> queue = queues.get(user);
            if (threads.isShutdown() || waiting >= queueTotal
                    || (queue != null && queue.size() >= queuePerUser)) {
                return false;
            }
            first = queue == null;
            if (first) {
                queue = new ArrayDeque<>();
                queues.put(user, queue);
            }
            queue.add(webhook);
            waiting++;
        }
        if (first) {
            try {
                threads.execute(() -> sendNext(user));
            } catch (RejectedExecutionException e) {
                synchronized (this) {
                    waiting -= queues.remove(user).size();
                }
                return false;
            }
        }
        return true;
    }

    /**
     * Send the user's oldest webhook, then put the user at the back of the line
     * if more are waiting. Once the sender is closing, the thread carries on
     * with the same user instead, so their waiting webhooks still go out, in
     * order, until the close stops waiting.
     */
    private void sendNext(String user) {
        while (true) {
            Runnable webhook;
            synchronized (this) {
                webhook = queues.get(user).poll();
                waiting--;
            }
            try {
                webhook.run();
            } catch (RuntimeException e) {
                log.warn("AMFA webhook delivery failed: {}", e.getMessage());
            }
            synchronized (this) {
                if (queues.get(user).isEmpty() || stopped) {
                    waiting -= queues.remove(user).size();
                    return;
                }
            }
            try {
                threads.execute(() -> sendNext(user));
                return;
            } catch (RejectedExecutionException closing) {
                // Closing: carry on with this user here.
            }
        }
    }

    /** Stop taking webhooks, and give the waiting ones up to {@code waitMillis} to go out. */
    public void close(long waitMillis) {
        threads.shutdown();
        try {
            if (!threads.awaitTermination(waitMillis, TimeUnit.MILLISECONDS)) {
                stop();
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            stop();
        }
    }

    private void stop() {
        stopped = true;
        threads.shutdownNow();
    }
}
