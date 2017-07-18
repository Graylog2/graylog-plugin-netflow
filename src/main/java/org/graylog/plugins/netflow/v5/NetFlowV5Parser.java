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

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.util.ArrayList;

/**
 * {@link http
 * ://www.cisco.com/en/US/docs/net_mgmt/netflow_collection_engine/3.6/
 * user/guide/format.html}
 * 
 * @since 0.1.0
 * @author xeraph
 */
public class NetFlowV5Parser {
	public static NetFlowV5Packet parsePacket(byte[] b) {
		NetFlowV5Header h = parseHeader(b, 0, 24);
		ArrayList<NetFlowV5Record> records = new ArrayList<NetFlowV5Record>();

		int offset = 24;
		for (int i = 0; i < h.getCount(); i++) {
			records.add(parseRecord(b, offset, 48));
			offset += 48;
		}

		return new NetFlowV5Packet(h, records, b.length);
	}

	public static NetFlowV5Header parseHeader(byte[] b, int offset, int length) {
		NetFlowV5Header h = new NetFlowV5Header();
		ByteBuffer bb = ByteBuffer.wrap(b);
		h.setVersion(bb.getShort() & 0xffff);
		h.setCount(bb.getShort() & 0xffff);
		h.setSysUptime(bb.getInt() & 0xffffffffl);
		h.setUnixSecs(bb.getInt() & 0xffffffffl);
		h.setUnixNsecs(bb.getInt() & 0xffffffffl);
		h.setFlowSequence(bb.getInt() & 0xffffffffl);
		h.setEngineType(bb.get() & 0xff);
		h.setEngineId(bb.get() & 0xff);
		short s = bb.getShort();
		h.setSamplingMode((s >> 14) & 3);
		h.setSamplingInterval(s & 0x3fff);
		return h;
	}

	public static NetFlowV5Record parseRecord(byte[] b, int offset, int length) {
		ByteBuffer bb = ByteBuffer.wrap(b, offset, length);
		NetFlowV5Record r = new NetFlowV5Record();
		byte[] srcAddr = new byte[4];
		byte[] dstAddr = new byte[4];
		byte[] nextHop = new byte[4];

		bb.get(srcAddr);
		bb.get(dstAddr);
		bb.get(nextHop);

		r.setSrcAddr(parseIp(srcAddr));
		r.setDstAddr(parseIp(dstAddr));
		r.setNextHop(parseIp(nextHop));
		r.setInputIface(bb.getShort() & 0xffff);
		r.setOutputIface(bb.getShort() & 0xffff);
		r.setPacketCount(bb.getInt() & 0xffffffffl);
		r.setOctetCount(bb.getInt() & 0xffffffffl);
		r.setFirst(bb.getInt() & 0xffffffffl);
		r.setLast(bb.getInt() & 0xffffffffl);
		r.setSrcPort(bb.getShort() & 0xffff);
		r.setDstPort(bb.getShort() & 0xffff);
		bb.get(); // unused pad1
		r.setTcpFlags(bb.get());
		r.setProtocol(bb.get() & 0xff);
		r.setTos(bb.get() & 0xff);
		r.setSrcAs(bb.getShort() & 0xffff);
		r.setDstAs(bb.getShort() & 0xffff);
		r.setSrcMask(bb.get() & 0xff);
		r.setDstMask(bb.get() & 0xff);
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
