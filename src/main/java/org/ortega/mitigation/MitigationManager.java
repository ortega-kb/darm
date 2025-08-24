//package org.ortega.mitigation;
//
//import org.onlab.packet.*;
//import org.onosproject.core.ApplicationId;
//import org.onosproject.core.CoreService;
//import org.onosproject.net.*;
//import org.onosproject.net.device.DeviceService;
//import org.onosproject.net.flow.*;
//import org.onosproject.net.host.HostService;
//import org.onosproject.net.link.LinkService;
//import org.onosproject.net.packet.*;
//import org.onosproject.net.topology.TopologyService;
//import org.osgi.service.component.annotations.*;
//import org.slf4j.Logger;
//import org.slf4j.LoggerFactory;
//
//import java.util.*;
//import java.util.concurrent.ConcurrentHashMap;
//import java.util.concurrent.ExecutorService;
//import java.util.concurrent.Executors;
//import java.util.concurrent.TimeUnit;
//
//@Component(immediate = true)
//public class MitigationManager implements MitigationService {
//
//    private final Logger log = LoggerFactory.getLogger(getClass());
//
//    // Services
//    @Reference(cardinality = ReferenceCardinality.MANDATORY)
//    protected CoreService coreService;
//
//    @Reference(cardinality = ReferenceCardinality.MANDATORY)
//    protected FlowRuleService flowRuleService;
//
//    @Reference(cardinality = ReferenceCardinality.MANDATORY)
//    protected PacketService packetService;
//
//    @Reference(cardinality = ReferenceCardinality.MANDATORY)
//    protected DeviceService deviceService;
//
//    @Reference(cardinality = ReferenceCardinality.MANDATORY)
//    protected HostService hostService;
//
//    @Reference(cardinality = ReferenceCardinality.MANDATORY)
//    protected LinkService linkService;
//
//    @Reference(cardinality = ReferenceCardinality.MANDATORY)
//    protected TopologyService topologyService;
//
//    // Application components
//    private ApplicationId appId;
//    private final ExecutorService executor = Executors.newFixedThreadPool(4);
//    private final PacketProcessor packetProcessor = new InPacketProcessor();
//    private final Map<DeviceId, Map<IpAddress, Long>> flowStats = new ConcurrentHashMap<>();
//
//    @Activate
//    protected void activate() {
//        appId = coreService.registerApplication("org.ortega.mitigation");
//        packetService.addProcessor(packetProcessor, PacketProcessor.director(0));
//        requestIntercepts();
//        log.info("Mitigation Manager Started");
//    }
//
//    @Deactivate
//    protected void deactivate() {
//        packetService.removeProcessor(packetProcessor);
//        withdrawIntercepts();
//        executor.shutdown();
//        flowRuleService.removeFlowRulesById(appId);
//        log.info("Mitigation Manager Stopped");
//    }
//
//    private void requestIntercepts() {
//        TrafficSelector selector = DefaultTrafficSelector.builder()
//                .matchEthType(Ethernet.TYPE_IPV4)
//                .build();
//        packetService.requestPackets(selector, PacketPriority.CONTROL, appId);
//    }
//
//    private void withdrawIntercepts() {
//        TrafficSelector selector = DefaultTrafficSelector.builder()
//                .matchEthType(Ethernet.TYPE_IPV4)
//                .build();
//        packetService.cancelPackets(selector, PacketPriority.CONTROL, appId);
//    }
//
//    @Override
//    public void mitigateAttack(IpAddress victimIp) {
//        executor.execute(new TraceBackTask(victimIp));
//    }
//
//    private class TraceBackTask implements Runnable {
//        private final IpAddress victimIp;
//        private static final int MAX_HOPS = 10;
//
//        TraceBackTask(IpAddress victimIp) {
//            this.victimIp = victimIp;
//        }
//
//        @Override
//        public void run() {
//            Host victimHost = findHostByIp(victimIp);
//            if (victimHost == null) {
//                log.warn("Victim host not found for IP: {}", victimIp);
//                return;
//            }
//
//            DeviceId deviceId = victimHost.location().deviceId();
//            traceBackToSource(deviceId, victimHost.mac(), victimIp, MAX_HOPS);
//        }
//
//        private void traceBackToSource(DeviceId deviceId, MacAddress macAddress, IpAddress ipAddress, int ttl) {
//            if (ttl <= 0) return;
//
//            try {
//                // Step 1: Find flow entry with max bytes for this traffic
//                FlowEntry targetFlow = null;
//                long maxBytes = 0;
//                PortNumber inPort = PortNumber.ANY;
//
//                for (FlowEntry flowEntry : flowRuleService.getFlowEntries(deviceId)) {
//                    if (matchesTraffic(flowEntry, macAddress, ipAddress)) {
//                        if (flowEntry.bytes() > maxBytes) {
//                            maxBytes = flowEntry.bytes();
//                            targetFlow = flowEntry;
//                        }
//                    }
//                }
//
//                if (targetFlow == null) {
//                    log.debug("No matching flow entries found on device {}", deviceId);
//                    return;
//                }
//
//                // Step 2: Get input port from flow entry
//                inPort = getInPort(targetFlow.selector());
//
//                // Step 3: Check if host is connected to this port
//                for (Host host : hostService.getConnectedHosts(deviceId)) {
//                    if (host.location().port().equals(inPort)) {
//                        log.info("Found attacker host {} at port {}", host.id(), inPort);
//                        setFlowRule(deviceId, host.mac(), ipAddress, inPort);
//                        return;
//                    }
//                }
//
//                // Step 4: Trace back to previous device
//                ConnectPoint sourcePoint = new ConnectPoint(deviceId, inPort);
//                Set<Link> links = linkService.getIngressLinks(sourcePoint);
//
//                for (Link link : links) {
//                    log.debug("Tracing back to source via link: {}", link);
//                    traceBackToSource(link.src().deviceId(), macAddress, ipAddress, ttl - 1);
//                }
//
//            } catch (Exception e) {
//                log.error("Traceback failed for {} on device {}: {}", ipAddress, deviceId, e.getMessage());
//            }
//        }
//
//        private boolean matchesTraffic(FlowEntry flow, MacAddress macAddress, IpAddress ipAddress) {
//            // Simplified matching logic - should be enhanced for production
//            return flow.selector().criteria().stream()
//                    .anyMatch(criterion ->
//                            criterion.type() == Criterion.Type.ETH_DST &&
//                                    ((EthCriterion) criterion).mac().equals(macAddress)) ||
//                    flow.selector().criteria().stream()
//                            .anyMatch(criterion ->
//                                    criterion.type() == Criterion.Type.IPV4_DST &&
//                                            ((IPCriterion) criterion).ip().equals(ipAddress));
//        }
//
//        private PortNumber getInPort(TrafficSelector selector) {
//            return selector.getCriterion(Criterion.Type.IN_PORT) != null ?
//                    ((PortCriterion) selector.getCriterion(Criterion.Type.IN_PORT)).port() :
//                    PortNumber.ANY;
//        }
//
//        private void setFlowRule(DeviceId deviceId, MacAddress macAddress, IpAddress ipAddress, PortNumber port) {
//            TrafficSelector selector = buildTrafficSelector(macAddress, ipAddress, port);
//            TrafficTreatment treatment = DefaultTrafficTreatment.builder()
//                    .drop()
//                    .build();
//
//            FlowRule rule = DefaultFlowRule.builder()
//                    .forDevice(deviceId)
//                    .withSelector(selector)
//                    .withTreatment(treatment)
//                    .withPriority(10)
//                    .fromApp(appId)
//                    .makePermanent()
//                    .build();
//
//            flowRuleService.applyFlowRules(rule);
//            log.info("Blocking rule installed on {} for attacker {}", deviceId, macAddress);
//        }
//
//        private TrafficSelector buildTrafficSelector(MacAddress macAddress, IpAddress ipAddress, PortNumber port) {
//            TrafficSelector.Builder builder = DefaultTrafficSelector.builder();
//
//            if (!macAddress.equals(MacAddress.NONE)) {
//                builder.matchEthSrc(macAddress);
//            }
//
//            if (!ipAddress.equals(IpAddress.NONE)) {
//                builder.matchIPSrc(ipAddress);
//            }
//
//            if (!port.equals(PortNumber.ANY)) {
//                builder.matchInPort(port);
//            }
//
//            return builder.build();
//        }
//    }
//
//    private class InPacketProcessor implements PacketProcessor {
//        @Override
//        public void process(PacketContext context) {
//            if (context.isHandled()) return;
//
//            Ethernet ethPacket = context.inPacket().parsed();
//            if (ethPacket == null || ethPacket.getEtherType() != Ethernet.TYPE_IPV4) return;
//
//            IPv4 ipv4Packet = (IPv4) ethPacket.getPayload();
//            IpAddress srcIp = IpAddress.valueOf(ipv4Packet.getSourceAddress());
//            IpAddress dstIp = IpAddress.valueOf(ipv4Packet.getDestinationAddress());
//            short protocol = ipv4Packet.getProtocol();
//
//            DeviceId deviceId = context.inPacket().receivedFrom().deviceId();
//            Map<IpAddress, Long> deviceStats = flowStats.computeIfAbsent(deviceId, k -> new ConcurrentHashMap<>());
//
//            deviceStats.merge(srcIp, 1L, Long::sum);
//            deviceStats.merge(dstIp, 1L, Long::sum);
//
//            context.block();
//        }
//    }
//
//    private Host findHostByIp(IpAddress ipAddress) {
//        return hostService.getHostsByIp(ipAddress).stream()
//                .findFirst()
//                .orElse(null);
//    }
//}