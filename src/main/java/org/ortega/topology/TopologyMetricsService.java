package org.ortega.topology;

import java.util.Map;

/**
 * Topology Metrics Service Interface.
 * This service is intended to provide metrics related to the network topology.
 */
public interface TopologyMetricsService {
    /**
     * Get the metrics of the network topology.
     * @return a map containing the metrics, where keys are metric names and values are their corresponding values.
     */
    Map<String, Object> getMetrics();
}
