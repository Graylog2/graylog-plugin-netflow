/**
 * Copyright (C) 2012, 2013, 2014 wasted.io Ltd <really@wasted.io>
 * Copyright (C) 2015 Graylog, Inc. (hello@graylog.org)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.graylog.plugins.netflow.flows;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;

import org.graylog.plugins.netflow.codecs.TemplateStore;
import org.graylog2.plugin.journal.RawMessage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.InetSocketAddress;

public class NetFlowParser {
    private static final Logger LOG = LoggerFactory.getLogger(NetFlowParser.class);

    public static NetFlowPacket parse(RawMessage rawMessage, TemplateStore v9templates) throws FlowException {
        final InetSocketAddress sender = rawMessage.getRemoteAddress() != null ? rawMessage.getRemoteAddress().getInetSocketAddress() : null;
        final ByteBuf buf = Unpooled.wrappedBuffer(rawMessage.getPayload());
        //System.out.println("Netflow parsers"); //TODO debug
        switch (buf.getUnsignedShort(0)) {
            case 5:
            	//System.exit(2);
            	return NetFlowV5Packet.parse(sender, buf);
            case 9:
            	//System.exit(1);
            	//This class is created by NetFlowCodec
            	//NetFlowPlugModule calls NetFlowCodec
            	//v9templates is a singleton to track v9 template flowSets
            	return NetFlowV9Packet.parse(sender, buf, v9templates);
            default:
                final RawMessage.SourceNode sourceNode = rawMessage.getSourceNodes().get(rawMessage.getSourceNodes().size() - 1);
                final String inputId = sourceNode == null ? "<unknown>" : sourceNode.inputId;
                LOG.warn("Unsupported NetFlow version {} on input {} (source: {})", buf.getUnsignedShort(0),
                        inputId,
                        rawMessage.getRemoteAddress().getInetSocketAddress());
                return null;
        }
    }
}