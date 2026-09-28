/*
 * SPDX-License-Identifier: Apache-2.0
 */
package org.keycloak.amfa.util;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.jboss.logging.Logger;
import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class EventUtil {

    private static final Logger logger = Logger.getLogger(EventUtil.class);
    private static final ObjectMapper mapper = new ObjectMapper();

    public static Map<String, Object> convertEventToMap(Object eventEntity) {
        Map<String, Object> result = new HashMap<>();

        try {
            // get event properties
            Method getIdMethod = eventEntity.getClass().getMethod("getId");
            Method getUserIdMethod = eventEntity.getClass().getMethod("getUserId");
            Method getTypeMethod = eventEntity.getClass().getMethod("getType");
            Method getTimeMethod = eventEntity.getClass().getMethod("getTime");
            Method getClientIdMethod = eventEntity.getClass().getMethod("getClientId");
            Method getDetailsJsonMethod = eventEntity.getClass().getMethod("getDetailsJson");
            Method getIpAddressMethod = eventEntity.getClass().getMethod("getIpAddress");

            result.put("id", getIdMethod.invoke(eventEntity));
            result.put("userId", getUserIdMethod.invoke(eventEntity));
            result.put("type", getTypeMethod.invoke(eventEntity));
            result.put("time", getTimeMethod.invoke(eventEntity));
            result.put("clientId", getClientIdMethod.invoke(eventEntity));
            result.put("ipAddress", getIpAddressMethod.invoke(eventEntity));

            // Parse details JSON
            String detailsJson = (String) getDetailsJsonMethod.invoke(eventEntity);
            if (detailsJson != null && !detailsJson.isEmpty()) {
                Map<String, Object> details = new HashMap<>();
                JsonNode detailsNode = mapper.readTree(detailsJson);
                Iterator<Map.Entry<String, JsonNode>> fields = detailsNode.fields();
                while (fields.hasNext()) {
                    Map.Entry<String, JsonNode> field = fields.next();
                    details.put(field.getKey(), field.getValue().asText());
                }
                result.put("details", details);

                // Extract risk level specifically for easier access
                if (detailsNode.has("risk_level")) {
                    result.put("riskLevel", detailsNode.get("risk_level").asText());
                }
            }
            return result;
        } catch (Exception e) {
            logger.error("Error converting event to map", e);
            return Map.of("error", "Failed to convert event");
        }
    }
}