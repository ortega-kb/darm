package org.ortega;

public final class OsgiPropertyConstants {
    private OsgiPropertyConstants() {}

    // Metric collection interval (seconds)
    public static final String INTERVAL_METRICS = "intervalMetrics";
    public static final int INTERVAL_METRICS_DEFAULT = 2;

    // Minimum packets to consider traffic present
    public static final String TRAFFIC_THRESHOLD = "trafficThreshold";
    public static final long TRAFFIC_THRESHOLD_DEFAULT = 10;

    // Inactivity timeout before stopping collection (seconds)
    public static final String INACTIVITY_TIMEOUT = "inactivityTimeout";
    public static final int INACTIVITY_TIMEOUT_DEFAULT = 10;

    // Kafka configuration
    public static final String KAFKA_BOOTSTRAP_SERVERS = "kafkaBootstrapServers";
    public static final String KAFKA_BOOTSTRAP_SERVERS_DEFAULT = "localhost:9092";
    public static final String KAFKA_TOPIC = "kafkaTopic";
    public static final String KAFKA_TOPIC_DEFAULT = "network-metrics";
}