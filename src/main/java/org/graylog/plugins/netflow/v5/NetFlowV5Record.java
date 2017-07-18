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
import java.util.HashMap;
import java.util.Map;

/**
 * @since 0.1.0
 * @author xeraph
 */
public class NetFlowV5Record {
	// bytes 0-3
	private InetAddress srcAddr;

	// bytes 4-7
	private InetAddress dstAddr;

	// bytes 8-11
	private InetAddress nextHop;

	// bytes 12-13, snmp index of input interface
	private int inputIface;

	// bytes 14-15, snmp index of output interface
	private int outputIface;

	// bytes 16-19, packets in flow
	private long packetCount;

	// bytes 20-23, total number of L3 bytes in the packets of the flow
	private long octetCount;

	// bytes 24-27, sysuptime at start of flow
	private long first;

	// bytes 28-31, sysuptime at the time the last packet of the flow was
	// received
	private long last;

	// bytes 32-33
	private int srcPort;

	// bytes 34-35
	private int dstPort;

	// bytes 37
	private byte tcpFlags;

	// bytes 38, ip protocol type (e.g. tcp = 6, udp = 17)
	private int protocol;

	// bytes 39, type of service
	private int tos;

	// bytes 40-41, source AS number
	private int srcAs;

	// bytes 42-43, destination AS number
	private int dstAs;

	// bytes 44
	private int srcMask;

	// bytes 45
	private int dstMask;

	public InetAddress getSrcAddr() {
		return srcAddr;
	}

	public void setSrcAddr(InetAddress srcAddr) {
		this.srcAddr = srcAddr;
	}

	public InetAddress getDstAddr() {
		return dstAddr;
	}

	public void setDstAddr(InetAddress dstAddr) {
		this.dstAddr = dstAddr;
	}

	public InetAddress getNextHop() {
		return nextHop;
	}

	public void setNextHop(InetAddress nextHop) {
		this.nextHop = nextHop;
	}

	public int getInputIface() {
		return inputIface;
	}

	public void setInputIface(int inputIface) {
		this.inputIface = inputIface;
	}

	public int getOutputIface() {
		return outputIface;
	}

	public void setOutputIface(int outputIface) {
		this.outputIface = outputIface;
	}

	public long getPacketCount() {
		return packetCount;
	}

	public void setPacketCount(long packetCount) {
		this.packetCount = packetCount;
	}

	public long getOctetCount() {
		return octetCount;
	}

	public void setOctetCount(long octetCount) {
		this.octetCount = octetCount;
	}

	public long getFirst() {
		return first;
	}

	public void setFirst(long first) {
		this.first = first;
	}

	public long getLast() {
		return last;
	}

	public void setLast(long last) {
		this.last = last;
	}

	public int getSrcPort() {
		return srcPort;
	}

	public void setSrcPort(int srcPort) {
		this.srcPort = srcPort;
	}

	public int getDstPort() {
		return dstPort;
	}

	public void setDstPort(int dstPort) {
		this.dstPort = dstPort;
	}

	public byte getTcpFlags() {
		return tcpFlags;
	}

	public void setTcpFlags(byte tcpFlags) {
		this.tcpFlags = tcpFlags;
	}

	public int getProtocol() {
		return protocol;
	}

	public void setProtocol(int protocol) {
		this.protocol = protocol;
	}

	public int getTos() {
		return tos;
	}

	public void setTos(int tos) {
		this.tos = tos;
	}

	public int getSrcAs() {
		return srcAs;
	}

	public void setSrcAs(int srcAs) {
		this.srcAs = srcAs;
	}

	public int getDstAs() {
		return dstAs;
	}

	public void setDstAs(int dstAs) {
		this.dstAs = dstAs;
	}

	public int getSrcMask() {
		return srcMask;
	}

	public void setSrcMask(int srcMask) {
		this.srcMask = srcMask;
	}

	public int getDstMask() {
		return dstMask;
	}

	public void setDstMask(int dstMask) {
		this.dstMask = dstMask;
	}

	public Map<String, Object> toMap() {
		HashMap<String, Object> m = new HashMap<String, Object>();
		m.put("src_addr", srcAddr.getHostAddress());
		m.put("dst_addr", dstAddr.getHostAddress());
		m.put("next_hop", nextHop.getHostAddress());
		m.put("input", inputIface);
		m.put("output", outputIface);
		m.put("packet_count", packetCount);
		m.put("octet_count", octetCount);
		m.put("first", first);
		m.put("last", last);
		m.put("src_port", srcPort);
		m.put("dst_port", dstPort);
		m.put("tcp_flags", tcpFlags & 0xff);
		m.put("protocol", protocol);
		m.put("tos", tos);
		m.put("src_as", srcAs);
		m.put("dst_as", dstAs);
		m.put("src_mask", srcMask);
		m.put("dst_mask", dstMask);
		return m;
	}

	@Override
	public String toString() {
		return "{src_addr=" + srcAddr + ", dst_addr=" + dstAddr + ", next_hop=" + nextHop + ", input=" + inputIface + ", output="
				+ outputIface + ", pkts=" + packetCount + ", octets=" + octetCount + ", first=" + first + ", last=" + last
				+ ", src_port=" + srcPort + ", dst_port=" + dstPort + ", tcpflags=" + tcpFlags + ", protocol=" + protocol
				+ ", tos=" + tos + ", src_as=" + srcAs + ", dst_as=" + dstAs + ", src_mask=" + srcMask + ", dst_mask=" + dstMask
				+ "}";
	}

}
