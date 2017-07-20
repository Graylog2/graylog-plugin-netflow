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
package org.graylog.plugins.netflow.v9;

import com.google.common.io.Resources;
import io.netty.buffer.Unpooled;
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

public class NetFlowV9ParserTest {
	@Test
	public void testParse() throws IOException {
		final byte[] b1 = Resources.toByteArray(Resources.getResource("netflow-data/netflow-v9-2-1.dat"));
		final byte[] b2 = Resources.toByteArray(Resources.getResource("netflow-data/netflow-v9-2-2.dat"));
		final byte[] b3 = Resources.toByteArray(Resources.getResource("netflow-data/netflow-v9-2-3.dat"));

		NetFlowV9TemplateCache cache = new NetFlowV9TemplateCache();

		// check header
		NetFlowV9Packet p1 = NetFlowV9Parser.parsePacket(Unpooled.wrappedBuffer(b1), cache);
		assertEquals(9, p1.getHeader().getVersion());
		assertEquals(3, p1.getHeader().getCount());
		assertEquals(0, p1.getHeader().getSequence());
		assertEquals(42212, p1.getHeader().getSysUptime());
		assertEquals(1369122709, p1.getHeader().getUnixSecs());
		assertEquals(106, p1.getHeader().getSourceId());

		// check templates
		assertEquals(2, p1.getTemplates().size());
		assertNotNull(p1.getOptionTemplate());

		NetFlowV9Template t1 = p1.getTemplates().get(0);
		assertEquals(257, t1.getTemplateId());
		assertEquals(18, t1.getFieldCount());

		List<NetFlowV9FieldDef> d1 = t1.getDefinitions();
		assertEquals("in_bytes", name(d1.get(0)));
		assertEquals("in_pkts", name(d1.get(1)));
		assertEquals("protocol", name(d1.get(2)));
		assertEquals("src_tos", name(d1.get(3)));
		assertEquals("tcp_flags", name(d1.get(4)));
		assertEquals("l4_src_port", name(d1.get(5)));
		assertEquals("ipv4_src_addr", name(d1.get(6)));
		assertEquals("src_mask", name(d1.get(7)));
		assertEquals("input_snmp", name(d1.get(8)));
		assertEquals("l4_dst_port", name(d1.get(9)));
		assertEquals("ipv4_dst_addr", name(d1.get(10)));
		assertEquals("dst_mask", name(d1.get(11)));
		assertEquals("output_snmp", name(d1.get(12)));
		assertEquals("ipv4_next_hop", name(d1.get(13)));
		assertEquals("src_as", name(d1.get(14)));
		assertEquals("dst_as", name(d1.get(15)));
		assertEquals("last_switched", name(d1.get(16)));
		assertEquals("first_switched", name(d1.get(17)));

		NetFlowV9Template t2 = p1.getTemplates().get(1);
		assertEquals(258, t2.getTemplateId());
		assertEquals(18, t2.getFieldCount());

		NetFlowV9Packet p2 = NetFlowV9Parser.parsePacket(Unpooled.wrappedBuffer(b2), cache);
		NetFlowV9Record r2 = p2.getRecords().get(0);
		Map<String, Object> f2 = r2.getFields();
		assertEquals(2818L, f2.get("in_bytes"));
		assertEquals(8L, f2.get("in_pkts"));
		assertEquals("192.168.124.1", f2.get("ipv4_src_addr"));
		assertEquals("239.255.255.250", f2.get("ipv4_dst_addr"));
		assertEquals(3072, f2.get("l4_src_port"));
		assertEquals(1900, f2.get("l4_dst_port"));
		assertEquals(17, f2.get("protocol"));

		NetFlowV9Packet p3 = NetFlowV9Parser.parsePacket(Unpooled.wrappedBuffer(b3), cache);
		assertEquals(1, p3.getRecords().size());
	}

	private String name(NetFlowV9FieldDef def) {
		return def.getType().name().toLowerCase();
	}
}
