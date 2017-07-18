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

import io.netty.buffer.ByteBuf;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;

/**
 * {@link http
 * ://www.cisco.com/en/US/docs/net_mgmt/netflow_collection_engine/3.6/
 * user/guide/format.html}
 * 
 * @since 0.1.0
 * @author xeraph
 */
public class NetFlowV5Parser {
    public static NetFlowV5Packet parsePacket(ByteBuf bb) {
        NetFlowV5Header header = parseHeader(bb.slice(0, 24));
        List<NetFlowV5Record> records = new ArrayList<>();

        int offset = 24;
        for (int i = 0; i < header.getCount(); i++) {
            records.add(parseRecord(bb.slice(offset, 48)));
            offset += 48;
        }

        return new NetFlowV5Packet(header, records, offset);
    }

    public static NetFlowV5Header parseHeader(ByteBuf bb) {
        NetFlowV5Header h = new NetFlowV5Header();
        h.setVersion(bb.readUnsignedShort());
        h.setCount(bb.readUnsignedShort());
        h.setSysUptime(bb.readUnsignedInt());
        h.setUnixSecs(bb.readUnsignedInt());
        h.setUnixNsecs(bb.readUnsignedInt());
        h.setFlowSequence(bb.readUnsignedInt());
        h.setEngineType(bb.readUnsignedByte());
        h.setEngineId(bb.readUnsignedByte());
        short s = bb.readShort();
        h.setSamplingMode((s >> 14) & 3);
        h.setSamplingInterval(s & 0x3fff);
        return h;
    }

    public static NetFlowV5Record parseRecord(ByteBuf bb) {
        NetFlowV5Record r = new NetFlowV5Record();
        byte[] srcAddr = new byte[4];
        byte[] dstAddr = new byte[4];
        byte[] nextHop = new byte[4];

        bb.readBytes(srcAddr);
        bb.readBytes(dstAddr);
        bb.readBytes(nextHop);

        r.setSrcAddr(parseIp(srcAddr));
        r.setDstAddr(parseIp(dstAddr));
        r.setNextHop(parseIp(nextHop));
        r.setInputIface(bb.readUnsignedShort());
        r.setOutputIface(bb.readUnsignedShort());
        r.setPacketCount(bb.readUnsignedInt());
        r.setOctetCount(bb.readUnsignedInt());
        r.setFirst(bb.readUnsignedInt());
        r.setLast(bb.readUnsignedInt());
        r.setSrcPort(bb.readUnsignedShort());
        r.setDstPort(bb.readUnsignedShort());
        bb.readByte(); // unused pad1
        r.setTcpFlags(bb.readByte());
        r.setProtocol(bb.readUnsignedByte());
        r.setTos(bb.readUnsignedByte());
        r.setSrcAs(bb.readUnsignedShort());
        r.setDstAs(bb.readUnsignedShort());
        r.setSrcMask(bb.readUnsignedByte());
        r.setDstMask(bb.readUnsignedByte());
        return r;
    }

    private static InetAddress parseIp(byte[] b) {
        try {
            return InetAddress.getByAddress(b);
        } catch (UnknownHostException e) {
            return null;
        }
    }
}
