package org.ortega;

import org.apache.kafka.common.serialization.Serializer;
import java.util.Map;

public class OsgiStringSerializer implements Serializer<String> {

    private final Serializer<String> stringSerializer = new org.apache.kafka.common.serialization.StringSerializer();

    @Override
    public void configure(Map<String, ?> configs, boolean isKey) {
        stringSerializer.configure(configs, isKey);
    }

    @Override
    public byte[] serialize(String topic, String data) {
        return stringSerializer.serialize(topic, data);
    }


    @Override
    public void close() {
        stringSerializer.close();
    }
}