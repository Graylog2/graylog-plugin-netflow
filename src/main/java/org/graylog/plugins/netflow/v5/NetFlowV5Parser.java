/*
 * Copyright 2013 Eediom Inc.
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
package org.graylog.plugins.netflow.v5;

import com.google.common.collect.ImmutableList;
import io.netty.buffer.ByteBuf;
import org.graylog.plugins.netflow.flows.CorruptFlowPacketException;
import org.graylog.plugins.netflow.flows.InvalidFlowVersionException;
import org.graylog.plugins.netflow.utils.ByteBufUtils;

import java.net.InetAddress;

import static org.graylog.plugins.netflow.v5.NetFlowV5Header.HEADER_LENGTH;
import static org.graylog.plugins.netflow.v5.NetFlowV5Record.RECORD_LENGTH;

public class NetFlowV5Parser {
    public static NetFlowV5Packet parsePacket(ByteBuf bb) {
        final int readableBytes = bb.readableBytes();

        final NetFlowV5Header header = parseHeader(bb.slice(0, HEADER_LENGTH));
        final int packetLength = HEADER_LENGTH + header.count() * RECORD_LENGTH;
        if (header.count() <= 0 || readableBytes < packetLength) {
            throw new CorruptFlowPacketException("Insufficient data (expected: " + packetLength + " bytes, actual: " + readableBytes + " bytes)");
        }

        final ImmutableList.Builder<NetFlowV5Record> records = ImmutableList.builder();
        int offset = HEADER_LENGTH;
        for (int i = 0; i < header.count(); i++) {
            records.add(parseRecord(bb.slice(offset, RECORD_LENGTH)));
            offset += RECORD_LENGTH;
        }

        return NetFlowV5Packet.create(header, records.build(), offset);
    }

    public static NetFlowV5Header parseHeader(ByteBuf bb) {
        final int version = bb.readUnsignedShort();
        if (version != 5) {
            throw new InvalidFlowVersionException(version);
        }

        final int count = bb.readUnsignedShort();
        final long sysUptime = bb.readUnsignedInt();
        final long unixSecs = bb.readUnsignedInt();
        final long unixNsecs = bb.readUnsignedInt();
        final long flowSequence = bb.readUnsignedInt();
        final short engineType = bb.readUnsignedByte();
        final short engineId = bb.readUnsignedByte();
        final short sampling = bb.readShort();
        final int samplingMode = (sampling >> 14) & 3;
        final int samplingInterval = sampling & 0x3fff;

        return NetFlowV5Header.create(
                version,
                count,
                sysUptime,
                unixSecs,
                unixNsecs,
                flowSequence,
                engineType,
                engineId,
                samplingMode,
                samplingInterval);
    }

    public static NetFlowV5Record parseRecord(ByteBuf bb) {
        final InetAddress srcAddr = ByteBufUtils.readInetAddress(bb);
        final InetAddress dstAddr = ByteBufUtils.readInetAddress(bb);
        final InetAddress nextHop = ByteBufUtils.readInetAddress(bb);
        final int inputIface = bb.readUnsignedShort();
        final int outputIface = bb.readUnsignedShort();
        final long packetCount = bb.readUnsignedInt();
        final long octetCount = bb.readUnsignedInt();
        final long first = bb.readUnsignedInt();
        final long last = bb.readUnsignedInt();
        final int srcPort = bb.readUnsignedShort();
        final int dstPort = bb.readUnsignedShort();
        bb.readByte(); // unused pad1
        final short tcpFlags = bb.readUnsignedByte();
        final short protocol = bb.readUnsignedByte();
        final short tos = bb.readUnsignedByte();
        final int srcAs = bb.readUnsignedShort();
        final int dstAs = bb.readUnsignedShort();
        final short srcMask = bb.readUnsignedByte();
        final short dstMask = bb.readUnsignedByte();

        return NetFlowV5Record.create(srcAddr, dstAddr, nextHop, inputIface, outputIface, packetCount, octetCount, first, last, srcPort, dstPort, tcpFlags, protocol, tos, srcAs, dstAs, srcMask, dstMask);
    }
}
