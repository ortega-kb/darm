package org.ortega.topology;

import org.onosproject.net.flow.FlowEntry;
import org.onosproject.net.flow.criteria.Criterion;
import org.onosproject.net.flow.criteria.IcmpTypeCriterion;

import java.math.BigDecimal;
import java.math.RoundingMode;
import java.util.Map;

/**
 * Utility class for Topology Metrics.
 */
public class TopologyMetricsUtil {

    private TopologyMetricsUtil() {
        // Prevent instantiation
    }

    /**
     * Converts bytes to bits.
     *
     * @param bytes the number of bytes
     * @return the equivalent number of bits
     */
    public static long bytesToBits(long bytes) {
        return bytes * 8;
    }

    /**
     * Converts bits to bytes.
     *
     * @param bits the number of bits
     * @return the equivalent number of bytes
     */
    public static long bitsToBytes(long bits) {
        return bits / 8;
    }

    /**
     * Checks if the given flow entry is an ICMP response.
     * @param flowEntry the flow entry to check
     * @return true if the flow entry is an ICMP response, false otherwise
     */
    public static boolean isIcmpResponse(FlowEntry flowEntry) {
        Criterion typeCriterion = flowEntry.selector().getCriterion(Criterion.Type.ICMPV4_TYPE);

        if (!(typeCriterion instanceof IcmpTypeCriterion)) {
            return false;
        }

        byte type = (byte) ((IcmpTypeCriterion) typeCriterion).icmpType();
        return type == 0;
    }

    /**
     * Computes the entropy of a given set of counts.
     *
     * @param counts a map where keys are items and values are their counts
     * @return the entropy value
     */
    public static <K> double computeEntropy(Map<K, Long> counts) {
        long total = counts.values().stream().mapToLong(Long::longValue).sum();
        if (total <= 0) {
            return 0.0;
        }

        double rawEntropy = counts.values().stream()
                .mapToDouble(c -> {
                    double p = (double) c / total;
                    return p == 0 ? 0.0 : -p * (Math.log(p) / Math.log(2));
                })
                .sum();

        // Round the entropy to 4 decimal places
        BigDecimal bigDecimalEntropy = new BigDecimal(String.valueOf(rawEntropy));
        return bigDecimalEntropy.setScale(4, RoundingMode.HALF_UP).doubleValue();
    }

}
