/**
 * Copyright (C) 2012, 2013, 2014 wasted.io Ltd <really@wasted.io>
 * Copyright (C) 2015-2017 Graylog, Inc. (hello@graylog.org)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/*
 * Copyright 2017 Graylog Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.graylog.plugins.netflow.codecs;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.collect.Maps;
import com.google.inject.assistedinject.Assisted;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufUtil;
import io.netty.buffer.Unpooled;
import org.graylog.plugins.netflow.flows.FlowException;
import org.graylog.plugins.netflow.flows.NetFlowFormatter;
import org.graylog.plugins.netflow.v5.NetFlowV5Packet;
import org.graylog.plugins.netflow.v5.NetFlowV5Parser;
import org.graylog.plugins.netflow.v9.NetFlowV9FieldTypeRegistry;
import org.graylog.plugins.netflow.v9.NetFlowV9Packet;
import org.graylog.plugins.netflow.v9.NetFlowV9Parser;
import org.graylog.plugins.netflow.v9.NetFlowV9Record;
import org.graylog2.plugin.Message;
import org.graylog2.plugin.ResolvableInetSocketAddress;
import org.graylog2.plugin.configuration.Configuration;
import org.graylog2.plugin.configuration.ConfigurationRequest;
import org.graylog2.plugin.configuration.fields.ConfigurationField;
import org.graylog2.plugin.configuration.fields.TextField;
import org.graylog2.plugin.inputs.annotations.Codec;
import org.graylog2.plugin.inputs.annotations.ConfigClass;
import org.graylog2.plugin.inputs.annotations.FactoryClass;
import org.graylog2.plugin.inputs.codecs.AbstractCodec;
import org.graylog2.plugin.inputs.codecs.CodecAggregator;
import org.graylog2.plugin.inputs.codecs.MultiMessageCodec;
import org.graylog2.plugin.inputs.transports.NettyTransport;
import org.graylog2.plugin.journal.RawMessage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.inject.Inject;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

@Codec(name = "netflow", displayName = "NetFlow")
public class NetFlowCodec extends AbstractCodec implements MultiMessageCodec {
    private static final Logger LOG = LoggerFactory.getLogger(NetFlowCodec.class);

    @VisibleForTesting
    static final String CK_NETFLOW9_DEFINITION_PATH = "netflow9_definitions_Path";

    /**
     * Marker byte which signals that the contained netflow packet should be parsed as is.
     */
    public static final byte PASSTHROUGH_MARKER = 0x00;
    /**
     * Marker byte which signals that the contained netflow v9 packet is non-RFC:
     * It contains all necessary template flows before any data flows and can be completely parsed without a template cache.
     */
    public static final byte ORDERED_V9_MARKER = 0x01;

    private final NetFlowV9FieldTypeRegistry typeRegistry;

    @Inject
    protected NetFlowCodec(@Assisted Configuration configuration) throws IOException {
        super(configuration);

        final String netFlow9DefinitionsPath = configuration.getString(CK_NETFLOW9_DEFINITION_PATH);
        if (netFlow9DefinitionsPath == null || netFlow9DefinitionsPath.trim().isEmpty()) {
            this.typeRegistry = NetFlowV9FieldTypeRegistry.create();
        } else {
            try (InputStream inputStream = new FileInputStream(netFlow9DefinitionsPath)) {
                this.typeRegistry = NetFlowV9FieldTypeRegistry.create(inputStream);
            }
        }
    }

    @Nullable
    @Override
    public CodecAggregator getAggregator() {
        // this is intentional: we replace the entire channel handler in NetFlowUdpTransport because we need a different signature
        return null;
    }

    @Nullable
    @Override
    public Message decode(@Nonnull RawMessage rawMessage) {
        throw new UnsupportedOperationException("MultiMessageCodec " + getClass() + " does not support decode()");
    }

    @Nullable
    @Override
    public Collection<Message> decodeMessages(@Nonnull RawMessage rawMessage) {
        try {
            final ResolvableInetSocketAddress remoteAddress = rawMessage.getRemoteAddress();
            final InetSocketAddress sender = remoteAddress != null ? remoteAddress.getInetSocketAddress() : null;

            final byte[] payload = rawMessage.getPayload();
            if(payload.length < 3) {
                LOG.debug("NetFlow message (source: {}) doesn't even fit the NetFlow version (size: {} bytes)",
                        sender, payload.length);
                return null;
            }

            final ByteBuf buffer = Unpooled.wrappedBuffer(payload);
            switch (buffer.readByte()) {
                case PASSTHROUGH_MARKER:
                    final NetFlowV5Packet netFlowV5Packet = NetFlowV5Parser.parsePacket(buffer);

                    return netFlowV5Packet.records().stream()
                            .map(record ->  NetFlowFormatter.toMessage(netFlowV5Packet.header(), record, sender))
                            .collect(Collectors.toList());
                case ORDERED_V9_MARKER:
                    // our "custom" netflow v9 that has all the templates in the same packet
                    final NetFlowV9Packet netFlowV9Packet = NetFlowV9Parser.parsePacket(buffer, typeRegistry, Maps.newHashMap());
                    return netFlowV9Packet.records().stream()
                            .filter(record -> record instanceof NetFlowV9Record)
                        .map(record ->  NetFlowFormatter.toMessage(netFlowV9Packet.header(), record, sender))
                        .collect(Collectors.toList());
                default:
                    final List<RawMessage.SourceNode> sourceNodes = rawMessage.getSourceNodes();
                    final RawMessage.SourceNode sourceNode = sourceNodes.isEmpty() ? null : sourceNodes.get(sourceNodes.size() - 1);
                    final String inputId = sourceNode == null ? "<unknown>" : sourceNode.inputId;
                    LOG.warn("Unsupported NetFlow packet on input {} (source: {})", inputId, sender);
                    return null;
            }
        } catch (FlowException e) {
            LOG.error("Error parsing NetFlow packet <{}> received from <{}>", rawMessage.getId(), rawMessage.getRemoteAddress(), e);
            if (LOG.isDebugEnabled()) {
                LOG.debug("NetFlow packet hexdump:\n{}", ByteBufUtil.prettyHexDump(Unpooled.wrappedBuffer(rawMessage.getPayload())));
            }
            return null;
        }
    }

    @FactoryClass
    public interface Factory extends AbstractCodec.Factory<NetFlowCodec> {
        @Override
        NetFlowCodec create(Configuration configuration);

        @Override
        Config getConfig();
    }

    @ConfigClass
    public static class Config extends AbstractCodec.Config {
        @Override
        public void overrideDefaultValues(@Nonnull ConfigurationRequest cr) {
            if (cr.containsField(NettyTransport.CK_PORT)) {
                cr.getField(NettyTransport.CK_PORT).setDefaultValue(2055);
            }
        }

        @Override
        public ConfigurationRequest getRequestedConfiguration() {
            final ConfigurationRequest configuration = super.getRequestedConfiguration();
            configuration.addField(new TextField(CK_NETFLOW9_DEFINITION_PATH, "Netflow 9 field definitions", "", "Path to the YAML file containing Netflow 9 field definitions", ConfigurationField.Optional.OPTIONAL));
            return configuration;
        }
    }
}
