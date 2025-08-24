/*
 * Copyright 2025-present Open Networking Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.ortega.api;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.onosproject.rest.AbstractWebResource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

/**
 * DDoS Attack Recognition and Mitigation REST API Resource.
 */
@Path("ddos-alert")
public class AppWebResource extends AbstractWebResource {
    private final Logger log = LoggerFactory.getLogger(getClass());
    private final ObjectMapper mapper = new ObjectMapper();

    /**
     * Receive DDoS alerts.
     *
     * @param jsonNode Alert data in JSON format
     * @return HTTP Response
     */
    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response receiveAlert(InputStream inputStream) {
        try {
            // Parse and validate the alert structure
            JsonNode jsonNode = mapper.readTree(inputStream);
            DdosAlert alert = parseAlert(jsonNode);

            log.warn("Received DDoS Alert [Confidence: {}]: {}",
                    alert.confidence, alert.toString());

            // TODO: Add your alert processing logic here

            return Response.ok().entity(buildSuccessResponse(alert)).build();
        } catch (AlertValidationException e) {
            log.error("Invalid alert format: {}", e.getMessage());
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(buildErrorResponse(e.getMessage()))
                    .build();
        } catch (Exception e) {
            log.error("Error processing alert", e);
            return Response.serverError()
                    .entity(buildErrorResponse("Internal server error"))
                    .build();
        }
    }

    private DdosAlert parseAlert(JsonNode node) throws AlertValidationException {
        DdosAlert alert = new DdosAlert();

        // Validate and extract timestamp
        if (!node.has("timestamp")) {
            throw new AlertValidationException("Missing 'timestamp' field");
        }
        alert.timestamp = node.get("timestamp").asDouble();

        // Validate and extract features
        if (!node.has("features") || !node.get("features").isObject()) {
            throw new AlertValidationException("Missing or invalid 'features' object");
        }
        JsonNode features = node.get("features");
        alert.features = new HashMap<>();
        Iterator<Map.Entry<String, JsonNode>> fields = features.fields();
        while (fields.hasNext()) {
            Map.Entry<String, JsonNode> entry = fields.next();
            alert.features.put(entry.getKey(), entry.getValue().asDouble());
        }

        // Validate and extract probability
        if (!node.has("probability")) {
            throw new AlertValidationException("Missing 'probability' field");
        }
        alert.probability = node.get("probability").asDouble();

        // Validate and extract confidence
        if (!node.has("confidence")) {
            throw new AlertValidationException("Missing 'confidence' field");
        }
        alert.confidence = node.get("confidence").asText();

        // Validate and extract verification checks
        if (!node.has("verification_checks") || !node.get("verification_checks").isObject()) {
            throw new AlertValidationException("Missing or invalid 'verification_checks' object");
        }
        JsonNode checks = node.get("verification_checks");
        alert.verificationChecks = new HashMap<>();
        Iterator<Map.Entry<String, JsonNode>> checkFields = checks.fields();
        while (checkFields.hasNext()) {
            Map.Entry<String, JsonNode> entry = checkFields.next();
            alert.verificationChecks.put(entry.getKey(), entry.getValue().asBoolean());
        }

        // Extract model version (optional)
        if (node.has("model_version")) {
            alert.modelVersion = node.get("model_version").asText();
        } else {
            alert.modelVersion = "1.0"; // Default
        }

        return alert;
    }

    private ObjectNode buildSuccessResponse(DdosAlert alert) {
        ObjectNode response = mapper().createObjectNode();
        response.put("status", "success");
        response.put("message", "Alert processed successfully");
        response.put("alert_id", alert.timestamp);
        return response;
    }

    private ObjectNode buildErrorResponse(String message) {
        ObjectNode response = mapper().createObjectNode();
        response.put("status", "error");
        response.put("message", message);
        return response;
    }

    /**
     * Custom exception for alert validation errors.
     */
    private static class AlertValidationException extends Exception {
        public AlertValidationException(String message) {
            super(message);
        }
    }

    /**
     * Internal DDoS Alert representation.
     */
    private static class DdosAlert {
        public double timestamp;
        public Map<String, Double> features;
        public double probability;
        public String confidence;
        public Map<String, Boolean> verificationChecks;
        public String modelVersion;

        @Override
        public String toString() {
            return String.format(
                    "DDoS Alert [%.2f] - Confidence: %s, Probability: %.2f%%, " +
                            "Features: %s, Checks: %s, Model: %s",
                    timestamp, confidence, probability * 100,
                    features, verificationChecks, modelVersion
            );
        }
    }
}