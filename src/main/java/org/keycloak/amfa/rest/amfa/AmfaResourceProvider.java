/*
 * SPDX-License-Identifier: Apache-2.0
 */
package org.keycloak.amfa.rest.amfa;

import org.keycloak.amfa.authenticator.adaptiveauth.AdaptiveAuthUtils;
import org.keycloak.amfa.rest.model.AdaptiveAuthConfig;
import org.keycloak.amfa.rest.model.AdaptiveAuthConfigParameter;
import org.keycloak.amfa.rest.model.Country;
import org.keycloak.amfa.rest.model.ErrorResponse;
import org.keycloak.amfa.rest.model.ScoringConfigDTO;
import org.keycloak.amfa.service.Guards;
import org.keycloak.amfa.service.AmfaApiService;
import org.keycloak.amfa.service.serviceaccount.ServiceAccountNotConfiguredException;
import org.keycloak.amfa.service.serviceaccount.ServiceAccountService;
import org.keycloak.amfa.util.AmfaHttp;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.vavr.control.Either;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.apache.http.conn.ConnectTimeoutException;
import org.jboss.resteasy.reactive.NoCache;
import org.keycloak.http.simple.SimpleHttpResponse;
import org.keycloak.models.GroupModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.representations.AccessToken;
import org.keycloak.services.resource.RealmResourceProvider;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.io.InputStream;
import java.net.ConnectException;
import java.net.SocketTimeoutException;
import java.net.URISyntaxException;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

@Slf4j
public class AmfaResourceProvider implements RealmResourceProvider {

    public static final String COUNTRY_NAME_ARRAY = "countryNameArray";
    private static final String ADAPTIVE_AUTH_API_CLIENT_ID = "adaptive-auth-api";

    /**
     * How long the settings and scoring calls wait on the engine. Keycloak's
     * client sets no connect timeout, so an engine address that drops packets
     * held the admin page for about 75s, and only its 5s default bounded the
     * read. Now both end in the same "engine unreachable" error. Longer than
     * the 5s of the login calls, as nobody waits at a login prompt here and a
     * save can take longer than a read.
     */
    private static final int ENGINE_TIMEOUT_MILLIS = 10000;
    private static final ObjectMapper objectMapper = new ObjectMapper();
    private static final Map<String, String> countryNameToCodeMap = loadCountryMap();

    private final KeycloakSession session;
    private final AmfaApiService apiService;

    public AmfaResourceProvider(KeycloakSession session, AmfaApiService apiService) {
        this.session = session;
        this.apiService = apiService;
    }

    @Override
    public Object getResource() {
        return this;
    }

    @Override
    public void close() {

    }

    /**
     * Fetch the active adaptive-MFA risk parameters for the current realm.
     * Proxies to the AMFA engine's GET /{realm}/settings using a service-account token.
     */
    @Path("fetchAdaptiveMFAParameters")
    @GET
    @NoCache
    @Consumes(MediaType.APPLICATION_JSON)
    public Response fetchAdaptiveMFAParameters(@HeaderParam("Authorization") String token)
            throws URISyntaxException, IOException {

        Either<Response, AccessToken> auth = Guards.authenticateRealmAdminRequest(session, token);
        if (auth.isLeft()) return auth.getLeft();

        Either<Response, String> serviceAccountToken = engineToken("fetchAdaptiveMFAParameters");
        if (serviceAccountToken.isLeft()) return serviceAccountToken.getLeft();

        try {
            SimpleHttpResponse httpResponse = AmfaHttp
                    .create(session, ENGINE_TIMEOUT_MILLIS)
                    .doGet(adaptiveAuthUrl("/settings"))
                    .auth(serviceAccountToken.get())
                    .asResponse();
            if (httpResponse.getStatus() >= 300) {
                log.error("fetchAdaptiveMFAParameters: httpResponse={}", httpResponse);
                return createErrorResponse(Response.Status.BAD_GATEWAY,
                        "AMFA engine returned HTTP " + httpResponse.getStatus()
                                + ": " + httpResponse.asString());
            }
            return Response.ok(httpResponse.asJson(), MediaType.APPLICATION_JSON_TYPE).build();
        } catch (IOException e) {
            log.error("fetchAdaptiveMFAParameters: AMFA engine unreachable", e);
            return createErrorResponse(Response.Status.BAD_GATEWAY,
                    "AMFA engine unreachable: " + unreachableReason(e, ENGINE_TIMEOUT_MILLIS));
        }
    }

    /**
     * Persist adaptive-MFA risk parameters for the current realm.
     * The UI sends a parameter list plus an {@code extraParameter} object carrying
     * whitelist/blacklist arrays; those are merged into the parameters before the
     * payload is forwarded to the AMFA engine's PUT /{realm}/settings.
     */
    @Path("updateAdaptiveMFAParameters")
    @POST
    @NoCache
    @Consumes(MediaType.APPLICATION_JSON)
    public Response updateAdaptiveMFAParameters(@HeaderParam("Authorization") String token, AdaptiveAuthConfig config)
            throws IOException, URISyntaxException {

        Either<Response, AccessToken> auth = Guards.authenticateRealmAdminRequest(session, token);
        if (auth.isLeft()) return auth.getLeft();

        Either<Response, String> serviceAccountToken = engineToken("updateAdaptiveMFAParameters");
        if (serviceAccountToken.isLeft()) return serviceAccountToken.getLeft();

        List<AdaptiveAuthConfigParameter> parameters = config.getParameters();
        JsonNode parametersNode = objectMapper.valueToTree(parameters);
        JsonNode extraParameterNode = objectMapper.valueToTree(config.getExtraParameter());
        updatedParameters(parametersNode, extraParameterNode);

        try {
            SimpleHttpResponse httpResponse = AmfaHttp
                    .create(session, ENGINE_TIMEOUT_MILLIS)
                    .doPut(adaptiveAuthUrl("/settings"))
                    .auth(serviceAccountToken.get())
                    .json(parametersNode)
                    .asResponse();
            if (httpResponse.getStatus() >= 300) {
                log.error("updateAdaptiveMFAParameters: httpResponse={}", httpResponse);
                return createErrorResponse(Response.Status.BAD_GATEWAY,
                        "AMFA engine returned HTTP " + httpResponse.getStatus()
                                + ": " + httpResponse.asString());
            }
            return Response.ok(httpResponse.asJson(), MediaType.APPLICATION_JSON_TYPE).build();
        } catch (IOException e) {
            log.error("updateAdaptiveMFAParameters: AMFA engine unreachable", e);
            return createErrorResponse(Response.Status.BAD_GATEWAY,
                    "AMFA engine unreachable: " + unreachableReason(e, ENGINE_TIMEOUT_MILLIS));
        }
    }

    /** Static list of countries used by the geolocation white/blacklist selectors. */
    @Path("countries")
    @GET
    @NoCache
    @Consumes(MediaType.APPLICATION_JSON)
    public Response getAllCountries() {
        try {
            InputStream inputStream = getClass().getClassLoader().getResourceAsStream("countries.json");
            List<Country> countries = objectMapper.readValue(inputStream,
                    objectMapper.getTypeFactory().constructCollectionType(List.class, Country.class));
            String json = objectMapper.writeValueAsString(countries);
            return Response.ok(json, MediaType.APPLICATION_JSON).build();
        } catch (IOException e) {
            return Response.serverError().build();
        }
    }

    /** Realm groups, used to scope per-group parameter sets in the admin UI. */
    @Path("groups")
    @GET
    @NoCache
    @Consumes(MediaType.APPLICATION_JSON)
    public Response getGroups(@HeaderParam("Authorization") String token) {
        Either<Response, AccessToken> auth = Guards.authenticateRealmAdminRequest(session, token);
        if (auth.isLeft()) return auth.getLeft();

        Either<String, Stream<GroupModel>> result = apiService.getGroups();
        if (result.isLeft()) {
            return Response.status(Response.Status.BAD_REQUEST).build();
        }
        return Response.ok(result.get(), MediaType.APPLICATION_JSON).build();
    }

    /**
     * Fetch the per-realm risk-scoring config (mode/bias/thresholds).
     * Proxies to the AMFA engine's GET /{realm}/scoring.
     */
    @Path("fetchScoringConfig")
    @GET
    @NoCache
    @Consumes(MediaType.APPLICATION_JSON)
    public Response fetchScoringConfig(@HeaderParam("Authorization") String token)
            throws URISyntaxException, IOException {

        Either<Response, AccessToken> auth = Guards.authenticateRealmAdminRequest(session, token);
        if (auth.isLeft()) return auth.getLeft();

        Either<Response, String> serviceAccountToken = engineToken("fetchScoringConfig");
        if (serviceAccountToken.isLeft()) return serviceAccountToken.getLeft();

        try {
            SimpleHttpResponse httpResponse = AmfaHttp
                    .create(session, ENGINE_TIMEOUT_MILLIS)
                    .doGet(adaptiveAuthUrl("/scoring"))
                    .auth(serviceAccountToken.get())
                    .asResponse();
            if (httpResponse.getStatus() >= 300) {
                log.error("fetchScoringConfig: httpResponse={}", httpResponse);
                return createErrorResponse(Response.Status.BAD_GATEWAY,
                        "AMFA engine returned HTTP " + httpResponse.getStatus()
                                + ": " + httpResponse.asString());
            }
            return Response.ok(httpResponse.asJson(), MediaType.APPLICATION_JSON_TYPE).build();
        } catch (IOException e) {
            log.error("fetchScoringConfig: AMFA engine unreachable", e);
            return createErrorResponse(Response.Status.BAD_GATEWAY,
                    "AMFA engine unreachable: " + unreachableReason(e, ENGINE_TIMEOUT_MILLIS));
        }
    }

    /**
     * Persist the per-realm risk-scoring config.
     * Proxies to the AMFA engine's PUT /{realm}/scoring.
     */
    @Path("updateScoringConfig")
    @POST
    @NoCache
    @Consumes(MediaType.APPLICATION_JSON)
    public Response updateScoringConfig(@HeaderParam("Authorization") String token, ScoringConfigDTO config)
            throws URISyntaxException, IOException {

        Either<Response, AccessToken> auth = Guards.authenticateRealmAdminRequest(session, token);
        if (auth.isLeft()) return auth.getLeft();

        Either<Response, String> serviceAccountToken = engineToken("updateScoringConfig");
        if (serviceAccountToken.isLeft()) return serviceAccountToken.getLeft();

        try {
            SimpleHttpResponse httpResponse = AmfaHttp
                    .create(session, ENGINE_TIMEOUT_MILLIS)
                    .doPut(adaptiveAuthUrl("/scoring"))
                    .auth(serviceAccountToken.get())
                    .json(objectMapper.valueToTree(config))
                    .asResponse();
            if (httpResponse.getStatus() >= 300) {
                log.error("updateScoringConfig: httpResponse={}", httpResponse);
                return createErrorResponse(Response.Status.BAD_GATEWAY,
                        "AMFA engine returned HTTP " + httpResponse.getStatus()
                                + ": " + httpResponse.asString());
            }
            return Response.ok(httpResponse.asJson(), MediaType.APPLICATION_JSON_TYPE).build();
        } catch (IOException e) {
            log.error("updateScoringConfig: AMFA engine unreachable", e);
            return createErrorResponse(Response.Status.BAD_GATEWAY,
                    "AMFA engine unreachable: " + unreachableReason(e, ENGINE_TIMEOUT_MILLIS));
        }
    }

    /**
     * The adaptive-auth-api token for an engine call, or the answer to give instead.
     *
     * <p>A realm without an engine endpoint, or without that client or its secret, is
     * not set up for AMFA: it gets a 409 saying what is missing. A token request that
     * fails gets a 502 with the reason. Before, the engine was called without a token,
     * or at a URL with no host, and the page only learned that the engine answered 401
     * or could not be reached.
     */
    private Either<Response, String> engineToken(String operation) {
        RealmModel realm = session.getContext().getRealm();
        String endpoint = realm.getAttribute(AdaptiveAuthUtils.ADAPTIVE_AUTH_ENDPOINT);
        if (endpoint == null || endpoint.isBlank()) {
            return Either.left(notSetUp(operation, realm, "no AMFA engine endpoint is set"));
        }
        try {
            return Either.right(ServiceAccountService.requestServiceAccountToken(
                    realm, session, ADAPTIVE_AUTH_API_CLIENT_ID));
        } catch (ServiceAccountNotConfiguredException e) {
            return Either.left(notSetUp(operation, realm, e.getMessage()));
        } catch (IOException e) {
            log.error("{}: could not get a token for the {} client", operation, ADAPTIVE_AUTH_API_CLIENT_ID, e);
            return Either.left(createErrorResponse(Response.Status.BAD_GATEWAY,
                    "Could not get a token for the " + ADAPTIVE_AUTH_API_CLIENT_ID + " client: "
                            + unreachableReason(e, ServiceAccountService.TOKEN_TIMEOUT_MILLIS)));
        }
    }

    private Response notSetUp(String operation, RealmModel realm, String reason) {
        log.warn("{}: Adaptive MFA is not set up for realm {}: {}", operation, realm.getName(), reason);
        return createErrorResponse(Response.Status.CONFLICT, "Adaptive MFA is not set up for this realm: " + reason);
    }

    /**
     * Why a call failed, in words an admin can act on. Java's own message for a host
     * it cannot resolve is only the host name, and a timeout's does not say how long
     * was waited.
     */
    static String unreachableReason(IOException e, int timeoutMillis) {
        String message = e.getMessage() == null ? "" : e.getMessage();
        if (e instanceof UnknownHostException) {
            int colon = message.indexOf(':');
            return "unknown host '" + (colon < 0 ? message : message.substring(0, colon)).trim() + "'";
        }
        if (e instanceof ConnectTimeoutException || e instanceof SocketTimeoutException) {
            return "no answer within " + timeoutMillis / 1000 + " seconds (" + message + ")";
        }
        if (e instanceof ConnectException) {
            return "connection failed (" + message + ")";
        }
        return message.isBlank() ? e.getClass().getSimpleName() : message;
    }

    private String adaptiveAuthUrl(String suffix) {
        String endpoint = session.getContext().getRealm().getAttribute(AdaptiveAuthUtils.ADAPTIVE_AUTH_ENDPOINT);
        if (endpoint == null) endpoint = "";
        return endpoint.concat("/" + session.getContext().getRealm().getName() + suffix);
    }

    private void updatedParameters(JsonNode parametersNode, JsonNode extraParameterNode) {
        if (extraParameterNode == null || extraParameterNode.isNull() || extraParameterNode.isEmpty()) {
            return;
        }
        processParameter(parametersNode, extraParameterNode, "operating_system", "osArray");
        processParameter(parametersNode, extraParameterNode, "ip_address", "ipAddressArray");
        processParameter(parametersNode, extraParameterNode, "anonymous_detection", "vpnMaskArray");
        processParameter(parametersNode, extraParameterNode, "date_time", "timeArray");
        processParameter(parametersNode, extraParameterNode, "country_name", COUNTRY_NAME_ARRAY);
    }

    private void processParameter(JsonNode parametersNode, JsonNode extraParameterNode, String parameterName,
                                  String extraParameterArrayName) {
        JsonNode parameterArrayNode = extraParameterNode.get(extraParameterArrayName);
        if (parameterArrayNode != null && parameterArrayNode.isArray()) {
            Iterator<JsonNode> parameterIterator = parameterArrayNode.elements();
            for (JsonNode parameter : parametersNode) {
                if (parameter.get("parameter_name").asText().equals(parameterName) && parameterIterator.hasNext()) {
                    JsonNode parameterNode = parameterIterator.next();

                    JsonNode whitelistNode = parameterNode.get("whitelist");
                    List<String> whitelistValues = new ArrayList<>();
                    if (whitelistNode != null && whitelistNode.isArray()) {
                        for (JsonNode value : whitelistNode) {
                            String val = value.asText();
                            if (COUNTRY_NAME_ARRAY.equals(extraParameterArrayName)) {
                                val = mapCountryNameToCode(val);
                            }
                            whitelistValues.add(val);
                        }
                        ((ObjectNode) parameter).putPOJO("whitelist", whitelistValues);
                    }

                    JsonNode blacklistNode = parameterNode.get("blacklist");
                    List<String> blacklistValues = new ArrayList<>();
                    if (blacklistNode != null && blacklistNode.isArray()) {
                        for (JsonNode value : blacklistNode) {
                            String val = value.asText();
                            if (COUNTRY_NAME_ARRAY.equals(extraParameterArrayName)) {
                                val = mapCountryNameToCode(val);
                            }
                            blacklistValues.add(val);
                        }
                        ((ObjectNode) parameter).putPOJO("blacklist", blacklistValues);
                    }

                    String groupId = parameterNode.has("group_id") ? parameterNode.get("group_id").asText() : "default";
                    ((ObjectNode) parameter).put("group_id", groupId);
                }
            }
        }
    }

    private static Map<String, String> loadCountryMap() {
        try (InputStream inputStream =
                     AmfaResourceProvider.class.getClassLoader().getResourceAsStream("countries.json")) {
            JsonNode root = objectMapper.readTree(inputStream);
            Map<String, String> countryMap = new HashMap<>();
            for (JsonNode country : root) {
                if (country.has("name") && country.has("code")) {
                    countryMap.put(country.get("name").asText().toLowerCase(), country.get("code").asText());
                }
            }
            return countryMap;
        } catch (IOException e) {
            log.error("Failed to load or parse countries.json", e);
            throw new RuntimeException("Failed to load or parse countries.json", e);
        }
    }

    private String mapCountryNameToCode(String name) {
        return countryNameToCodeMap.getOrDefault(name.toLowerCase(), name);
    }

    private Response createErrorResponse(Response.Status status, String message) {
        ErrorResponse errorResponse = new ErrorResponse(message);
        return Response.status(status)
                .entity(errorResponse)
                .type(MediaType.APPLICATION_JSON)
                .build();
    }
}


