package org.ortega.topology;

import org.onlab.packet.Ip4Address;
import org.onosproject.net.Device;
import org.onosproject.net.device.DeviceService;
import org.onosproject.net.flow.FlowEntry;
import org.onosproject.net.flow.FlowRuleService;
import org.onosproject.net.flow.criteria.Criterion;
import org.onosproject.net.flow.criteria.IPCriterion;
import org.onosproject.net.flow.criteria.IPProtocolCriterion;


import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.BiConsumer;
import java.util.logging.Logger;

import static org.ortega.topology.MetricsPropertyConstants.*;
import static org.ortega.topology.TopologyMetricsUtil.computeEntropy;
import static org.ortega.topology.TopologyMetricsUtil.isIcmpResponse;

/**
 * Topology Metrics Manager.
 * This class implements the TopologyMetricsService interface
 */
public class TopologyMetricsManager implements TopologyMetricsService {
    private final Logger log = Logger.getLogger(TopologyMetricsManager.class.getName());

    private final DeviceService deviceService;
    private final FlowRuleService flowRuleService;
    private final int intervalMetrics;

    // Atomic variables to keep track of the last collected metrics of bytes
    private final AtomicLong lastTotalBytes = new AtomicLong(0);

    public TopologyMetricsManager(
            DeviceService deviceService,
            FlowRuleService flowRuleService,
            int intervalMetrics
    ) {
        this.deviceService = deviceService;
        this.flowRuleService = flowRuleService;
        this.intervalMetrics = intervalMetrics;
    }

    @Override
    public Map<String, Object> getMetrics() {
        try {
            Map<String, Object> metrics = new HashMap<>();
            metrics.put(FRAMES, collectFrames());
            metrics.put(FLOWS, collectFlows());
            metrics.put(BPS, collectBps());
            metrics.put(SRC_ENTROPY, collectIpSrcEntropy());
            metrics.put(DST_ENTROPY, collectIpDstEntropy());
            metrics.put(PROTO_ENTROPY, collectProtoEntropy());

            return metrics;
        } catch (Exception e) {
            log.severe("Error collecting metrics: " + e.getMessage());
            return Map.of();
        }
    }

    /**
     * Collects the total number of frames in the network.
     *
     * @return the total number of frames
     */
    private long collectFrames() {
        long totalFrames = 0;
        for (Device device : deviceService.getDevices()) {
            Iterable<FlowEntry> flowEntries = flowRuleService.getFlowEntries(device.id());
            for (FlowEntry entry : flowEntries) {
                if (!entry.isPermanent()) {
                    totalFrames += entry.packets();
                }
            }
        }

        return totalFrames;
    }

    /**
     * Collects the total number of flows in the network.
     *
     * @return the total number of flows
     */
    private long collectFlows() {
        long totalFlows = 0;
        for (Device device : deviceService.getDevices()) {
            Iterable<FlowEntry> flowEntries = flowRuleService.getFlowEntries(device.id());
            for (FlowEntry entry : flowEntries) {
                if (!entry.isPermanent()) {
                    totalFlows++;
                }
            }
        }

        return totalFlows;
    }

    /**
     * Collects the total bytes per second (Bps) in the network.
     *
     * @return the total bytes per second
     */
    private long collectBps() {
        long totalBytes = 0;
        for (Device device : deviceService.getDevices()) {
            Iterable<FlowEntry> flowEntries = flowRuleService.getFlowEntries(device.id());
            for (FlowEntry entry : flowEntries) {
                if (!entry.isPermanent()) {
                    totalBytes += entry.bytes();
                }
            }
        }

        // Calculate delta between since the last collection and now
        long previousBytes = lastTotalBytes.getAndSet(totalBytes);
        long deltaBytes = totalBytes - previousBytes;

        if (deltaBytes < 0) {
            log.warning("Delta bytes is negative, resetting to zero.");
            deltaBytes = 0;
        }

        // Convert to bytes per second
        // divide by the interval in seconds
        return (deltaBytes * 8) / intervalMetrics;
    }

    /**
     * Collects the entropy of source IP addresses in the network.
     * This method iterates over all flow entries and computes the entropy based on the source IP address counts.
     *
     * @return the entropy value of source IP addresses
     */
    public double collectIpSrcEntropy() {
        try {
            Map<String, Long> ipSrcCounts = new HashMap<>();
            forEachFlow((flowEntry, packets) -> {
                if (!flowEntry.isPermanent() && !isIcmpResponse(flowEntry)) {
                    Criterion criterion = flowEntry.selector().getCriterion(Criterion.Type.IPV4_SRC);
                    if (criterion instanceof IPCriterion) {
                        Ip4Address ip = ((IPCriterion) criterion).ip().address().getIp4Address();
                        ipSrcCounts.merge(ip.toString(), packets, Long::sum);
                    }
                }
            });

            return computeEntropy(ipSrcCounts);
        } catch (Exception e) {
            log.severe("Error collecting IP source entropy: " + e.getMessage());
            return 0.0;
        }
    }

    /**
     * Collects the entropy of destination IP addresses in the network.
     * This method iterates over all flow entries and computes the entropy based on the destination IP address counts.
     *
     * @return the entropy value of destination IP addresses
     */
    public double collectIpDstEntropy() {
        try {
            Map<String, Long> ipDstCounts = new HashMap<>();
            forEachFlow((flowEntry, packets) -> {
                if (!flowEntry.isPermanent() && !isIcmpResponse(flowEntry)) {
                    Criterion criterion = flowEntry.selector().getCriterion(Criterion.Type.IPV4_DST);
                    if (criterion instanceof IPCriterion) {
                        Ip4Address ip = ((IPCriterion) criterion).ip().address().getIp4Address();
                        ipDstCounts.merge(ip.toString(), packets, Long::sum);
                    }
                }
            });

            return computeEntropy(ipDstCounts);
        } catch (Exception e) {
            log.severe("Error collecting IP destination entropy: " + e.getMessage());
            return 0.0;
        }
    }

    /**
     * Collects the entropy of protocol types in the network.
     * This method iterates over all flow entries and computes the entropy based on the protocol counts.
     *
     * @return the entropy value of protocols
     */
    public double collectProtoEntropy() {
        try {
            Map<String, Long> protoCounts = new HashMap<>();
            forEachFlow((flowEntry, packets) -> {
                if (!flowEntry.isPermanent()) {
                    Criterion criterion = flowEntry.selector().getCriterion(Criterion.Type.IP_PROTO);
                    if (criterion instanceof IPProtocolCriterion) {
                        short protocol = ((IPProtocolCriterion) criterion).protocol();
                        protoCounts.merge(String.valueOf(protocol), packets, Long::sum);
                    }
                }
            });
            return computeEntropy(protoCounts);
        } catch (Exception e) {
            log.severe("Error collecting protocol entropy: " + e.getMessage());
            return 0.0;
        }
    }

    /**
     * Iterates over all flow entries in the network and applies the given consumer function.
     *
     * @param consumer the function to apply to each flow entry
     */
    private void forEachFlow(BiConsumer<FlowEntry, Long> consumer) {
        for (Device device : deviceService.getDevices()) {
            for (FlowEntry fe : flowRuleService.getFlowEntries(device.id())) {
                consumer.accept(fe, fe.packets());
            }
        }
    }



}
