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
import com.google.common.collect.Lists;
import com.google.common.collect.Sets;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
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
import java.util.List;
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

    private final Cache<TemplateKey, Queue<ByteBuf>> flowCache;
    private final Cache<TemplateKey, ByteBuf> templateCache;

    @Inject
    public NetflowV9CodecAggregator() {
        // TODO customize
        this.templateCache = CacheBuilder.newBuilder()
                .maximumSize(5000)
                .recordStats()
                .build();
        flowCache = CacheBuilder.newBuilder()
                .expireAfterWrite(1, TimeUnit.MINUTES)
                .maximumWeight(Size.megabytes(1).toBytes())
                .<Object, Queue<ByteBuf>>weigher((key, value) -> value.stream().map(ByteBuf::readableBytes).reduce(0, Integer::sum))
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
            // We do not include a NetFlow V9 header, because technically this is not a netflow packet and we do not want to trick anyone into believing it is.

            final ByteBuf byteBuf = Unpooled.wrappedBuffer(buf.toByteBuffer());
            final RawNetFlowV9Packet rawNetFlowV9Packet = NetFlowV9Parser.parseIntoBuffers(byteBuf);
            final long sourceId = rawNetFlowV9Packet.header().sourceId();

            // the list of template keys to return in the result
            final Set<TemplateKey> templates = Sets.newHashSet();
            // this list of flows to return in the result
            final List<ChannelBuffer> flowBuffers = Lists.newArrayList();

            // register templates and check for buffered flows
            rawNetFlowV9Packet.templates().forEach((templateId, buffer) -> {
                final TemplateKey templateKey = new TemplateKey(remoteAddress, sourceId, templateId);
                templateCache.put(templateKey, buffer);
                // check for previously queued buffers for this template
                final Queue<ByteBuf> bufferedFlows = flowCache.getIfPresent(templateKey);
                if (bufferedFlows != null) {
                    templates.add(templateKey);
                    ByteBuf flow;
                    while (null != (flow = bufferedFlows.poll())) {
                        flowBuffers.add(ChannelBuffers.wrappedBuffer(flow.array()));
                    }
                }
            });

            // process the current flows
            rawNetFlowV9Packet.dataFlows().forEach((templateId, dataFlowBuffer) -> {
                final TemplateKey templateKey = new TemplateKey(remoteAddress, sourceId, templateId);
                final ByteBuf templateFlow = templateCache.getIfPresent(templateKey);
                if (templateFlow != null) {
                    // we have the template, so we can re-assemble it

                    final Queue<ByteBuf> bufferedFlows = flowCache.getIfPresent(templateKey);
                    if (bufferedFlows != null) {
                        templates.add(templateKey);
                        flowBuffers.add(ChannelBuffers.wrappedBuffer(dataFlowBuffer.nioBuffer()));
                    }
                } else {
                    // we don't know the template, save this flow for later
                    try {
                        final Queue<ByteBuf> byteBufs = flowCache.get(templateKey, ConcurrentLinkedQueue::new);
                        byteBufs.add(dataFlowBuffer);
                    } catch (ExecutionException ignored) {
                        // the loader cannot fail, it only creates a new queue
                    }
                }
            });
            // if we have any flows to forward, prepare a result
            if (!flowBuffers.isEmpty()) {
                final ChannelBuffer resultBuffer = ChannelBuffers.dynamicBuffer();
                resultBuffer.writeByte(NetFlowCodec.ORDERED_V9_MARKER);
                templates.stream()
                        .map(templateCache::getIfPresent)
                        .filter(obj -> {
                            if (obj == null) {
                                LOG.warn("Template expired while processing it");
                                return false;
                            } else {
                                return true;
                            }
                        })
                        .forEach(templateBuffer -> resultBuffer.writeBytes(templateBuffer.nioBuffer()));
                flowBuffers.forEach(resultBuffer::writeBytes);
                return new Result(resultBuffer, true);
            }

            return new Result(null, true);
        } catch (Exception e) {
            LOG.error("Unexpected failure while aggregating NetFlowV9 packet, discarding packet.", ExceptionUtils.getRootCause(e));
            return new Result(null, false);
        }
    }

}
