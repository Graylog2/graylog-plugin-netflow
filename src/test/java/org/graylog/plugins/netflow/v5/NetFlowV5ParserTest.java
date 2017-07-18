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

import com.google.common.io.Resources;
import org.junit.Test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

public class NetFlowV5ParserTest {
	@Test
	public void testParse1() throws IOException {
		final byte[] b = Resources.toByteArray(Resources.getResource("netflow-data/netflow-v5-1.dat"));
		NetFlowV5Packet packet = NetFlowV5Parser.parsePacket(b);
		assertNotNull(packet);

		NetFlowV5Header h = packet.getHeader();
		assertEquals(5, h.getVersion());
		assertEquals(2, h.getCount());
		assertEquals(3381L, h.getSysUptime());
		assertEquals(1430591888L, h.getUnixSecs());
		assertEquals(280328000, h.getUnixNsecs());

		final List<NetFlowV5Record> records = packet.getRecords();
		assertEquals(2, records.size());

		Map<String, Object> record1 = records.get(0).toMap();
		assertEquals("10.0.2.15", record1.get("dst_addr"));
		assertEquals(6, record1.get("protocol"));
		assertEquals(0, record1.get("src_as"));
		assertEquals("10.0.2.2", record1.get("src_addr"));
		assertEquals(2577L, record1.get("last"));
		assertEquals(22, record1.get("dst_port"));
		assertEquals(230L, record1.get("octet_count"));
		assertEquals(54435, record1.get("src_port"));
		assertEquals(0, record1.get("src_mask"));
		assertEquals(0, record1.get("tos"));
		assertEquals(0, record1.get("input"));
		assertEquals("0.0.0.0", record1.get("next_hop"));
		assertEquals(16, record1.get("tcp_flags"));
		assertEquals(0, record1.get("dst_as"));
		assertEquals(0, record1.get("output"));
		assertEquals(4294967295L, record1.get("first"));
		assertEquals(0, record1.get("dst_mask"));
		assertEquals(5L, record1.get("packet_count"));


		Map<String, Object> record2 = records.get(1).toMap();
		assertEquals("10.0.2.2", record2.get("dst_addr"));
		assertEquals(6, record2.get("protocol"));
		assertEquals(0, record2.get("src_as"));
		assertEquals("10.0.2.15", record2.get("src_addr"));
		assertEquals(2577L, record2.get("last"));
		assertEquals(54435, record2.get("dst_port"));
		assertEquals(304L, record2.get("octet_count"));
		assertEquals(22, record2.get("src_port"));
		assertEquals(0, record2.get("src_mask"));
		assertEquals(0, record2.get("tos"));
		assertEquals(0, record2.get("input"));
		assertEquals("0.0.0.0", record2.get("next_hop"));
		assertEquals(24, record2.get("tcp_flags"));
		assertEquals(0, record2.get("dst_as"));
		assertEquals(0, record2.get("output"));
		assertEquals(4294967295L, record2.get("first"));
		assertEquals(0, record2.get("dst_mask"));
		assertEquals(4L, record2.get("packet_count"));
	}

	@Test
	public void testParse2() throws IOException {
		final byte[] b = Resources.toByteArray(Resources.getResource("netflow-data/netflow-v5-2.dat"));
		NetFlowV5Packet packet = NetFlowV5Parser.parsePacket(b);
		assertNotNull(packet);

		NetFlowV5Header h = packet.getHeader();
		assertEquals(5, h.getVersion());
		assertEquals(30, h.getCount());
		assertEquals(234994, h.getSysUptime());
		assertEquals(1369017138, h.getUnixSecs());
		assertEquals(805, h.getUnixNsecs());

		assertEquals(30, packet.getRecords().size());
		Map<String, Object> r = packet.getRecords().get(0).toMap();
		assertEquals("192.168.124.20", r.get("dst_addr"));
		assertEquals(6, r.get("protocol"));
		assertEquals(0, r.get("src_as"));
		assertEquals("14.63.211.15", r.get("src_addr"));
		assertEquals(202992L, r.get("last"));
		assertEquals(47994, r.get("dst_port"));
		assertEquals(317221L, r.get("octet_count"));
		assertEquals(80, r.get("src_port"));
		assertEquals(0, r.get("src_mask"));
		assertEquals(0, r.get("tos"));
		assertEquals(0, r.get("input"));
		assertEquals("0.0.0.0", r.get("next_hop"));
		assertEquals(27, r.get("tcp_flags"));
		assertEquals(0, r.get("dst_as"));
		assertEquals(0, r.get("output"));
		assertEquals(202473L, r.get("first"));
		assertEquals(0, r.get("dst_mask"));
		assertEquals(110L, r.get("packet_count"));
	}
}
