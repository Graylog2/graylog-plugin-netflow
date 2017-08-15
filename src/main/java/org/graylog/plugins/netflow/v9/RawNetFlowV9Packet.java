package org.graylog.plugins.netflow.v9;

import com.google.auto.value.AutoValue;
import io.netty.buffer.ByteBuf;

import java.util.Map;

@AutoValue
public abstract class RawNetFlowV9Packet {

    public abstract NetFlowV9Header header();

    public abstract int dataLength();

    public abstract Map<Integer, ByteBuf> templates();

    public abstract Map<Integer, ByteBuf> dataFlows();

    public static RawNetFlowV9Packet create(NetFlowV9Header header, int dataLength, Map<Integer, ByteBuf> templates, Map<Integer, ByteBuf> dataFlows) {
        return new AutoValue_RawNetFlowV9Packet(header, dataLength, templates, dataFlows);
    }
}
