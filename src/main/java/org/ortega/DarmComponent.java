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
package org.ortega;

import org.apache.kafka.clients.producer.*;
import org.apache.kafka.common.serialization.StringSerializer;
import org.onlab.util.Tools;
import org.onosproject.cfg.ComponentConfigService;
import org.onosproject.net.Device;
import org.onosproject.net.device.DeviceService;
import org.onosproject.net.flow.FlowEntry;
import org.onosproject.net.flow.FlowRuleService;
import org.onosproject.net.flow.StoredFlowEntry;
import org.onosproject.net.packet.PacketContext;
import org.onosproject.net.packet.PacketProcessor;
import org.onosproject.net.packet.PacketService;
import org.onosproject.net.statistic.StatisticStore;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.ortega.topology.TopologyMetricsManager;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.Dictionary;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

import static org.ortega.OsgiPropertyConstants.*;
import static org.ortega.topology.MetricsPropertyConstants.*;

@Component(immediate = true,
        service = DarmComponent.class,
        property = {
                INTERVAL_METRICS + ":Integer=" + INTERVAL_METRICS_DEFAULT,
                TRAFFIC_THRESHOLD + ":Long=" + TRAFFIC_THRESHOLD_DEFAULT,
                INACTIVITY_TIMEOUT + ":Integer=" + INACTIVITY_TIMEOUT_DEFAULT,
                KAFKA_BOOTSTRAP_SERVERS + ":String=" + KAFKA_BOOTSTRAP_SERVERS_DEFAULT,
                KAFKA_TOPIC + ":String=" + KAFKA_TOPIC_DEFAULT
        })
public class DarmComponent {

    private final Logger log = LoggerFactory.getLogger(getClass());
    private final ObjectMapper jsonMapper = new ObjectMapper();

    // Services references
    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected ComponentConfigService cfgService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected FlowRuleService flowRuleService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected DeviceService deviceService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected PacketService packetService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected StatisticStore statisticStore;

    // Configuration properties
    private int intervalMetrics = INTERVAL_METRICS_DEFAULT;
    private long trafficThreshold = TRAFFIC_THRESHOLD_DEFAULT;
    private int inactivityTimeout = INACTIVITY_TIMEOUT_DEFAULT;
    private String kafkaBootstrapServers = KAFKA_BOOTSTRAP_SERVERS_DEFAULT;
    private String kafkaTopic = KAFKA_TOPIC_DEFAULT;

    // State management
    private final AtomicBoolean trafficDetected = new AtomicBoolean(false);
    private final AtomicLong lastTrafficTime = new AtomicLong(System.currentTimeMillis());
    private final AtomicReference<TopologyMetricsManager> metricsManager = new AtomicReference<>();

    // Executors
    private ScheduledExecutorService trafficMonitorExecutor;
    private ScheduledExecutorService metricsCollectorExecutor;

    // Kafka producer
    private KafkaProducer<String, String> kafkaProducer;

    // Packet processor for control plane traffic
    private final TrafficDetectionProcessor packetProcessor = new TrafficDetectionProcessor();

    @Activate
    protected void activate() {
        cfgService.registerProperties(getClass());
        packetService.addProcessor(packetProcessor, PacketProcessor.director(2));

        // Initialize Kafka producer
        initializeKafkaProducer();

        startTrafficMonitoring();
        log.info("DDoS Attack Recognition and Mitigation started with config: "
                        + "interval={}s, threshold={} packets, inactivity={}s, kafka={}",
                intervalMetrics, trafficThreshold, inactivityTimeout, kafkaBootstrapServers);
    }

    @Deactivate
    protected void deactivate() {
        cfgService.unregisterProperties(getClass(), false);
        packetService.removeProcessor(packetProcessor);
        stopAllExecutors();

        // Close Kafka producer
        if (kafkaProducer != null) {
            kafkaProducer.close();
            log.info("Kafka producer closed");
        }

        log.info("DDoS Attack Recognition and Mitigation stopped");
    }

    @Modified
    public void modified(ComponentContext context) {
        Dictionary<?, ?> properties = context != null ? context.getProperties() : new Properties();

        intervalMetrics = Tools.getIntegerProperty(properties, INTERVAL_METRICS, INTERVAL_METRICS_DEFAULT);
        trafficThreshold = Tools.getLongProperty(properties, TRAFFIC_THRESHOLD);
        inactivityTimeout = Tools.getIntegerProperty(properties, INACTIVITY_TIMEOUT, INACTIVITY_TIMEOUT_DEFAULT);
        kafkaBootstrapServers = getProperty(properties, KAFKA_BOOTSTRAP_SERVERS, KAFKA_BOOTSTRAP_SERVERS_DEFAULT);
        kafkaTopic = getProperty(properties, KAFKA_TOPIC, KAFKA_TOPIC_DEFAULT);

        // Reinitialize Kafka producer if config changed
        if (kafkaProducer != null) {
            kafkaProducer.close();
        }
        initializeKafkaProducer();

        log.info("Reconfigured: interval={}s, threshold={}, inactivity={}s, kafka={}",
                intervalMetrics, trafficThreshold, inactivityTimeout, kafkaBootstrapServers);
    }

    private String getProperty(Dictionary<?, ?> properties, String key, String defaultValue) {
        Object value = properties.get(key);
        return value != null ? value.toString() : defaultValue;
    }

    /**
     * Initializes Kafka producer with Docker-friendly configuration
     */
    private void initializeKafkaProducer() {
        try {
            Properties props = new Properties();
            props.put(ProducerConfig.BOOTSTRAP_SERVERS_CONFIG, kafkaBootstrapServers);

            props.put(ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG, OsgiStringSerializer.class);
            props.put(ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG, OsgiStringSerializer.class);

            // Optimizations for Docker environment
            props.put(ProducerConfig.ACKS_CONFIG, "1");
            props.put(ProducerConfig.RETRIES_CONFIG, 3);
            props.put(ProducerConfig.MAX_IN_FLIGHT_REQUESTS_PER_CONNECTION, 1);
            props.put(ProducerConfig.REQUEST_TIMEOUT_MS_CONFIG, 15000);
            props.put(ProducerConfig.DELIVERY_TIMEOUT_MS_CONFIG, 30000);

            // Compression for network efficiency
            // props.put(ProducerConfig.COMPRESSION_TYPE_CONFIG, "lz4");

            kafkaProducer = new KafkaProducer<>(props);
            log.info("Kafka producer initialized for topic: {}", kafkaTopic);
        } catch (Exception e) {
            log.error("Failed to initialize Kafka producer", e);
            throw new RuntimeException("Kafka producer initialization failed", e);
        }
    }

    /**
     * Starts the hybrid traffic monitoring system
     */
    private void startTrafficMonitoring() {
        trafficMonitorExecutor = Executors.newSingleThreadScheduledExecutor();
        metricsCollectorExecutor = Executors.newSingleThreadScheduledExecutor();

        // Main monitoring loop (runs every 2 seconds)
        trafficMonitorExecutor.scheduleWithFixedDelay(() -> {
            try {
                // Check both control plane and data plane traffic
                boolean hasTraffic = packetProcessor.hasRecentTraffic() || hasDataPlaneTraffic();

                if (hasTraffic) {
                    lastTrafficTime.set(System.currentTimeMillis());

                    // Start metrics collection if not already running
                    if (trafficDetected.compareAndSet(false, true)) {
                        startMetricsCollection();
                        log.debug("Traffic detected - Starting metrics collection");
                    }
                } else {
                    // Check for inactivity timeout
                    long quietTime = System.currentTimeMillis() - lastTrafficTime.get();
                    if (quietTime > inactivityTimeout * 1000L && trafficDetected.get()) {
                        trafficDetected.set(false);
                        stopMetricsCollection();
                        log.info("No traffic for {}s - Metrics collection stopped", inactivityTimeout);
                    }
                }
            } catch (Exception e) {
                log.error("Traffic monitoring error", e);
            }
        }, 0, 2, TimeUnit.SECONDS);
    }

    /**
     * Checks for data plane traffic using flow statistics
     */
    private boolean hasDataPlaneTraffic() {
        long totalPackets = 0;

        for (Device device : deviceService.getDevices()) {
            for (FlowEntry flow : flowRuleService.getFlowEntries(device.id())) {
                if (flow instanceof StoredFlowEntry) {
                    totalPackets += ((StoredFlowEntry) flow).packets();
                }
            }
        }

        return totalPackets > trafficThreshold;
    }

    /**
     * Starts periodic metrics collection
     */
    private void startMetricsCollection() {
        // Create new metrics manager for this session
        metricsManager.set(new TopologyMetricsManager(
                deviceService, flowRuleService, intervalMetrics
        ));

        metricsCollectorExecutor.scheduleAtFixedRate(() -> {
            try {
                TopologyMetricsManager manager = metricsManager.get();
                if (manager != null) {
                    Map<String, Object> metrics = manager.getMetrics();
                    if (isSignificantTraffic(metrics)) {
                        sendToKafka(metrics);
                    }
                }
            } catch (Exception e) {
                log.error("Metrics collection error", e);
            }
        }, 0, intervalMetrics, TimeUnit.SECONDS);
    }

    /**
     * Sends metrics to Kafka
     */
    private void sendToKafka(Map<String, Object> metrics) {
        try {
            // Convert metrics to JSON
            String json = jsonMapper.writeValueAsString(metrics);

            // Create Kafka record
            ProducerRecord<String, String> record = new ProducerRecord<>(kafkaTopic, json);

            // Send asynchronously with callback
            kafkaProducer.send(record, (metadata, exception) -> {
                if (exception != null) {
                    log.error("Failed to send metrics to Kafka topic {}", kafkaTopic, exception);
                } else {
                    log.debug("Metrics sent to Kafka [{}:{}]", metadata.topic(), metadata.partition());
                }
            });
        } catch (Exception e) {
            log.error("Kafka serialization/send error", e);
        }
    }

    /**
     * Stops metrics collection
     */
    private void stopMetricsCollection() {
        if (metricsCollectorExecutor != null) {
            metricsCollectorExecutor.shutdownNow();
            metricsCollectorExecutor = Executors.newSingleThreadScheduledExecutor();
        }
        metricsManager.set(null);
    }

    /**
     * Checks if traffic is significant enough to send
     */
    private boolean isSignificantTraffic(Map<String, Object> metrics) {
        long frames = (long) metrics.getOrDefault(FRAMES, 0L);
        long flows = (long) metrics.getOrDefault(FLOWS, 0L);
        return frames > trafficThreshold || flows > 0;
    }

    /**
     * Cleanly stops all executors
     */
    private void stopAllExecutors() {
        if (trafficMonitorExecutor != null) {
            trafficMonitorExecutor.shutdownNow();
        }
        if (metricsCollectorExecutor != null) {
            metricsCollectorExecutor.shutdownNow();
        }
    }

    /**
     * Custom packet processor for traffic detection
     */
    private static class TrafficDetectionProcessor implements PacketProcessor {
        private final AtomicLong lastPacketTime = new AtomicLong(0);

        @Override
        public void process(PacketContext context) {
            if (context.isHandled()) {
                return;
            }

            // Update last packet time
            lastPacketTime.set(System.currentTimeMillis());

            // Block packet to prevent further processing if needed
            context.block();
        }

        /**
         * Checks if we've seen control plane traffic recently
         */
        public boolean hasRecentTraffic() {
            return (System.currentTimeMillis() - lastPacketTime.get()) < 5000; // 5 seconds
        }
    }
}