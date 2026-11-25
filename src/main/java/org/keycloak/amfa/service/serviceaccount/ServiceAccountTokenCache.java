/*
 * SPDX-License-Identifier: Apache-2.0
 */
package org.keycloak.amfa.service.serviceaccount;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.LongSupplier;

/**
 * Service account tokens, reused until shortly before they expire.
 *
 * <p>Every login asked Keycloak for a fresh token twice, over HTTP (in the
 * auth-context step and in the decision step), and every admin page call once
 * more. A busy Keycloak got that token work on top of the logins themselves:
 * under load the requests timed out, and the engine was called without a token.
 *
 * <p>A token is reused until {@link #REFRESH_MARGIN_SECONDS} before it expires,
 * or half its lifetime when it lives shorter than twice that. In that last
 * stretch one caller fetches the next token while the others keep using the
 * one that is still valid, so a busy node does not send a burst of token
 * requests at each expiry. If that fetch fails, the still-valid token is used
 * until it expires, and the next caller tries again. An expired token is never
 * handed out. Each node keeps its own tokens; nothing is shared across a
 * cluster.
 */
final class ServiceAccountTokenCache {

    /** Replace a token this long before it expires. */
    static final long REFRESH_MARGIN_SECONDS = 30;
    /** Treat a token as expired this long before Keycloak's expiry, for clock skew and the call itself. */
    static final long EXPIRY_MARGIN_SECONDS = 5;

    private static final long NANOS_PER_SECOND = 1_000_000_000L;

    /** What a token request returned: the token and its lifetime in seconds (0 when not given). */
    record Fetched(String token, long expiresInSeconds) {
    }

    /** Asks Keycloak's token endpoint for a token. */
    @FunctionalInterface
    interface Fetcher {
        Fetched fetch() throws IOException;
    }

    /**
     * Everything a token depends on: the realm, the client, the token endpoint (its
     * address, which the user signed in at, sets the token's issuer) and the client
     * secret, so a rotated secret gets a new token. The secret is kept only as a
     * hash, and never printed.
     */
    static final class Key {
        private final String realmId;
        private final String clientId;
        private final String tokenEndpoint;
        private final String secretHash;

        Key(String realmId, String clientId, String tokenEndpoint, String clientSecret) {
            this.realmId = realmId;
            this.clientId = clientId;
            this.tokenEndpoint = tokenEndpoint;
            this.secretHash = sha256(clientSecret);
        }

        String realmId() {
            return realmId;
        }

        String clientId() {
            return clientId;
        }

        String tokenEndpoint() {
            return tokenEndpoint;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            if (!(o instanceof Key other)) {
                return false;
            }
            return Objects.equals(realmId, other.realmId) && Objects.equals(clientId, other.clientId)
                    && Objects.equals(tokenEndpoint, other.tokenEndpoint) && Objects.equals(secretHash, other.secretHash);
        }

        @Override
        public int hashCode() {
            return Objects.hash(realmId, clientId, tokenEndpoint, secretHash);
        }

        @Override
        public String toString() {
            return "Key[realm=" + realmId + ", client=" + clientId + ", tokenEndpoint=" + tokenEndpoint + "]";
        }

        private static String sha256(String value) {
            try {
                byte[] digest = MessageDigest.getInstance("SHA-256")
                        .digest(String.valueOf(value).getBytes(StandardCharsets.UTF_8));
                return HexFormat.of().formatHex(digest);
            } catch (NoSuchAlgorithmException e) {
                throw new IllegalStateException("SHA-256 is not available", e);
            }
        }
    }

    private static final class Cached {
        final String token;
        final long refreshAt;
        final long expiresAt;
        final AtomicBoolean refreshing = new AtomicBoolean();

        Cached(String token, long refreshAt, long expiresAt) {
            this.token = token;
            this.refreshAt = refreshAt;
            this.expiresAt = expiresAt;
        }
    }

    private final Map<Key, Cached> tokens = new ConcurrentHashMap<>();
    private final LongSupplier nanoTime;

    ServiceAccountTokenCache(LongSupplier nanoTime) {
        this.nanoTime = nanoTime;
    }

    /** A token for {@code key}: the cached one while it is good, otherwise a fresh one. */
    String get(Key key, Fetcher fetcher) throws IOException {
        long now = nanoTime.getAsLong();
        Cached cached = tokens.get(key);
        if (cached != null && now < cached.expiresAt) {
            if (now < cached.refreshAt || !cached.refreshing.compareAndSet(false, true)) {
                return cached.token;
            }
            try {
                return fetchAndKeep(key, fetcher);
            } catch (IOException | RuntimeException e) {
                // Still valid: use it, and let the next caller try the refresh.
                cached.refreshing.set(false);
                return cached.token;
            }
        }
        return fetchAndKeep(key, fetcher);
    }

    /** Drops a token the engine rejected, so the next call fetches a fresh one. */
    void forget(String token) {
        if (token != null) {
            tokens.values().removeIf(cached -> token.equals(cached.token));
        }
    }

    /** How many tokens are kept, for tests. */
    int size() {
        return tokens.size();
    }

    private String fetchAndKeep(Key key, Fetcher fetcher) throws IOException {
        long requestedAt = nanoTime.getAsLong();
        Fetched fetched = fetcher.fetch();
        long lifetime = fetched.expiresInSeconds();
        if (lifetime <= 0) {
            // Nothing says how long it lasts, so it is not kept.
            tokens.remove(key);
            return fetched.token();
        }
        // The token endpoint comes from the address the user signed in at, so a
        // Keycloak without a fixed hostname can see many: drop expired tokens
        // whenever one is stored, so they do not pile up.
        long now = nanoTime.getAsLong();
        tokens.values().removeIf(cached -> now >= cached.expiresAt);
        long refreshAfter = lifetime - Math.min(REFRESH_MARGIN_SECONDS, lifetime / 2);
        long usableFor = lifetime - Math.min(EXPIRY_MARGIN_SECONDS, lifetime / 4);
        tokens.put(key, new Cached(fetched.token(),
                requestedAt + refreshAfter * NANOS_PER_SECOND,
                requestedAt + usableFor * NANOS_PER_SECOND));
        return fetched.token();
    }
}
