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

import com.github.joschi.jadconfig.util.Size;
import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.google.common.collect.Maps;
import com.google.common.collect.Sets;
import com.google.protobuf.ByteString;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufUtil;
import io.netty.buffer.Unpooled;
import org.graylog.plugins.netflow.v9.NetFlowV9Journal;
import org.graylog.plugins.netflow.v9.NetFlowV9Parser;
import org.graylog.plugins.netflow.v9.RawNetFlowV9Packet;
import org.graylog2.shared.utilities.ExceptionUtils;
import org.jboss.netty.buffer.ChannelBuffer;
import org.jboss.netty.buffer.ChannelBuffers;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nonnull;
import javax.inject.Inject;
import java.net.SocketAddress;
import java.util.Map;
import java.util.Queue;
import java.util.Set;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;

/**
 * For Netflow v9 packets we want to prepend the corresponding flow template.
 * If we don't have that template yet, we consider the flow packet to be incomplete and continue to wait for the template.
 * TODO consider sharing seen templates between nodes in the cluster to minimize wait time
 */
public class NetflowV9CodecAggregator implements RemoteAddressCodecAggregator {
    private static final Logger LOG = LoggerFactory.getLogger(NetflowV9CodecAggregator.class);

    private static final ChannelBuffer PASSTHROUGH_MARKER = ChannelBuffers.wrappedBuffer(new byte[]{NetFlowCodec.PASSTHROUGH_MARKER});

    private final Cache<TemplateKey, Queue<ChannelBuffer>> packetCache;
    private final Cache<TemplateKey, TemplateByteBuf> templateCache;

    @Inject
    public NetflowV9CodecAggregator() {
        // TODO customize
        this.templateCache = CacheBuilder.newBuilder()
                .maximumSize(5000)
                .recordStats()
                .build();
        packetCache = CacheBuilder.newBuilder()
                .expireAfterWrite(1, TimeUnit.MINUTES)
                .maximumWeight(Size.megabytes(1).toBytes())
                .<Object, Queue<ChannelBuffer>>weigher((key, value) -> value.stream().map(ChannelBuffer::readableBytes).reduce(0, Integer::sum))
                .recordStats()
                .build();
    }

    @Nonnull
    @Override
    public Result addChunk(ChannelBuffer buf, SocketAddress remoteAddress) {
        if (buf.readableBytes() < 2) {
            // the buffer doesn't contain enough bytes to be a netflow packet, discard the packet
            return new Result(null, false);
        }

        try {
            final int netFlowVersion = buf.getShort(0);

            // only netflow v9 needs special treatment, everything else we just pass on
            if (netFlowVersion != 9) {
                return new Result(ChannelBuffers.wrappedBuffer(PASSTHROUGH_MARKER, buf), true);
            }

            // for NetFlow V9 we check that we have previously received template flows for each data flow.
            // if we do not have them yet, buffer the data flows until we receive a matching template
            // since we do not want to do that again in the codec, we will violate the RFC when putting together
            // the packets again:
            // the codec can, contrary to https://tools.ietf.org/html/rfc3954#section-9, assume that for each packet/RawMessage
            // the packet contains all necessary templates. This greatly simplifies parsing at the expense of larger RawMessages.

            // The rest of the code works as follows:
            // We shallowly parse the incoming packet, extracting all flows into ByteBufs.
            // We then cache the raw bytes for template flows, keyed by remote ip and source id. These are used to reassemble the packet for the journal later.
            // For each data flow that we do not have a matching template for yet, we put that into a queue.
            // Once the template flow arrives we go back through the queue and remove matching flows for further processing.
            final ByteBuf byteBuf = Unpooled.wrappedBuffer(buf.toByteBuffer());
            if (LOG.isTraceEnabled()) {
                LOG.trace("Received V9 packet:\n{}", ByteBufUtil.prettyHexDump(byteBuf));
            }
            final RawNetFlowV9Packet rawNetFlowV9Packet = NetFlowV9Parser.parsePacketShallow(byteBuf);
            final long sourceId = rawNetFlowV9Packet.header().sourceId();

            LOG.trace("Incoming NetFlow V9 packet contains: {}", rawNetFlowV9Packet);
            // the list of template keys to return in the result
            final Set<TemplateKey> templates = Sets.newHashSet();
            // this list of flows to return in the result
            final Set<ChannelBuffer> packetsToSend = Sets.newHashSet();

            // register templates and check for buffered flows
            rawNetFlowV9Packet.templates().forEach((templateId, buffer) -> {
                final TemplateKey templateKey = new TemplateKey(remoteAddress, sourceId, templateId);
                templateCache.put(templateKey, new TemplateByteBuf(buffer, false));
                // check for previously queued buffers for this template
                queueBufferedPackets(templates, packetsToSend, templateKey);

            });
            final Map.Entry<Integer, ByteBuf> optionTemplate = rawNetFlowV9Packet.optionTemplate();
            if (optionTemplate != null) {
                final TemplateKey templateKey = new TemplateKey(remoteAddress, sourceId, optionTemplate.getKey());
                templateCache.put(templateKey, new TemplateByteBuf(optionTemplate.getValue(), true));
                // check for previously queued buffers for this template
                queueBufferedPackets(templates, packetsToSend, templateKey);
            }

            final boolean[] packetBuffered = {false};
            // find out which templates we need to include for the current packet
            rawNetFlowV9Packet.usedTemplates().forEach(templateId -> {
                final TemplateKey templateKey = new TemplateKey(remoteAddress, sourceId, templateId);
                final TemplateByteBuf template = templateCache.getIfPresent(templateKey);
                if (template == null) {
                    // we don't have the template, this packet needs to be buffered until we receive the templates
                    try {
                        final Queue<ChannelBuffer> bufferedPackets = packetCache.get(templateKey, ConcurrentLinkedQueue::new);
                        bufferedPackets.add(buf);
                        packetBuffered[0] = true;
                    } catch (ExecutionException ignored) {
                        // the loader cannot fail, it only creates a new queue
                    }
                } else {
                    // include the template in our result
                    templates.add(templateKey);
                    packetsToSend.add(buf);
                }
            });

            // if we have buffered this packet, don't try to process it now. we still need all the templates for it
            if (packetBuffered[0]) {
                return new Result(null, true);
            }

            // if we didn't buffer anything but also didn't have anything queued that can be processed, don't proceed.
            if (packetsToSend.isEmpty()) {
                return new Result(null, true);
            }

            // if we have any packets to forward, prepare a result
            final ChannelBuffer resultBuffer = ChannelBuffers.dynamicBuffer();
            resultBuffer.writeByte(NetFlowCodec.ORDERED_V9_MARKER);

            final NetFlowV9Journal.RawNetflowV9.Builder builder = NetFlowV9Journal.RawNetflowV9.newBuilder();

            // add the used templates and option template to the journal message builder
            templates.stream()
                    .map(templateKey -> Maps.immutableEntry(templateKey, templateCache.getIfPresent(templateKey)))
                    .forEach(entry -> {
                        final TemplateKey templateKey = entry.getKey();
                        final TemplateByteBuf templateByteBuf = entry.getValue();
                        if (templateByteBuf == null) {
                            LOG.warn("Template {} expired while processing, discarding netflow packet", templateKey);
                        } else if (templateByteBuf.optionTemplate) {
                            LOG.debug("Writing options template flow {}", templateKey);
                            builder.putOptionTemplate(1, ByteString.copyFrom(templateByteBuf.buf.nioBuffer()));
                        } else {
                            LOG.debug("Writing template {}", templateKey);
                            builder.putTemplates(templateKey.getTemplateId(), ByteString.copyFrom(templateByteBuf.buf.nioBuffer()));
                        }
                    });

            // finally write out all the packets we had buffered as well as the current one
            packetsToSend.forEach(packetBuffer -> builder.addPackets(ByteString.copyFrom(packetBuffer.toByteBuffer())));
            resultBuffer.writeBytes(builder.build().toByteArray());
            return new Result(resultBuffer, true);

        } catch (Exception e) {
            LOG.error("Unexpected failure while aggregating NetFlowV9 packet, discarding packet.", ExceptionUtils.getRootCause(e));
            return new Result(null, false);
        }
    }

    private void queueBufferedPackets(Set<TemplateKey> templates, Set<ChannelBuffer> packetsToSend, TemplateKey templateKey) {
        final Queue<ChannelBuffer> bufferedFlows = packetCache.getIfPresent(templateKey);
        if (bufferedFlows != null) {
            templates.add(templateKey);
            ChannelBuffer previousPacket;
            LOG.debug("Adding {} previously buffered records", bufferedFlows.size());
            while (null != (previousPacket = bufferedFlows.poll())) {
                packetsToSend.add(ChannelBuffers.wrappedBuffer(previousPacket.toByteBuffer()));
            }
        }
    }

    private class TemplateByteBuf {
        private final boolean optionTemplate;
        ByteBuf buf;

        public TemplateByteBuf(ByteBuf buffer, boolean optionTemplate) {
            buf = buffer;
            this.optionTemplate = optionTemplate;
        }
    }
}
