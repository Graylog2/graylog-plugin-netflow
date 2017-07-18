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

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * 
 * {@link http://www.cisco.com/en/US/technologies/tk648/tk362/
 * technologies_white_paper09186a00800a3db9_ps6601_Products_White_Paper.html}
 * 
 * @since 0.1.0
 * @author xeraph
 */
public class NetFlowV9Parser {
	public static NetFlowV9Packet parsePacket(byte[] b, NetFlowV9TemplateCache cache) {
		NetFlowV9Packet p = new NetFlowV9Packet();
		p.setDataLength(b.length);
		ByteBuffer bb = ByteBuffer.wrap(b);
		NetFlowV9Header h = parseHeader(bb);

		p.setHeader(h);

		while (bb.hasRemaining()) {
			int flowSetId = bb.getShort() & 0xffff;
			if (flowSetId == 0) {
				List<NetFlowV9Template> tl = parseTemplates(bb);
				for (NetFlowV9Template t : tl)
					cache.getTemplates().put(t.getTemplateId(), t);

				p.setTemplates(tl);
			} else if (flowSetId == 1) {
				NetFlowV9OptionTemplate optTemplate = parseOptionTemplate(bb);
				p.setOptionTemplate(optTemplate);
				cache.setOptionTemplate(optTemplate);
			} else {
				bb.position(bb.position() - 2);
				List<NetFlowV9Record> r = parseRecords(bb, cache);
				p.setRecords(r);
			}
		}

		return p;
	}

	public static NetFlowV9Header parseHeader(ByteBuffer bb) {
		NetFlowV9Header h = new NetFlowV9Header();
		h.setVersion(bb.getShort() & 0xffff);
		h.setCount(bb.getShort() & 0xffff);
		h.setSysUptime(bb.getInt() & 0xffffffffl);
		h.setUnixSecs(bb.getInt() & 0xffffffffl);
		h.setSequence(bb.getInt() & 0xffffffffl);
		h.setSourceId(bb.getInt() & 0xffffffffl);

		return h;
	}

	public static List<NetFlowV9Template> parseTemplates(ByteBuffer bb) {
		List<NetFlowV9Template> templates = new ArrayList<NetFlowV9Template>();
		int len = bb.getShort() & 0xffff;

		int p = 4; // flow set id and length field itself
		while (p < len) {
			NetFlowV9Template t = new NetFlowV9Template();
			t.setTemplateId(bb.getShort() & 0xffff);
			t.setFieldCount(bb.getShort() & 0xffff);

			for (int i = 0; i < t.getFieldCount(); i++) {
				int fieldType = bb.getShort() & 0xffff;
				int fieldLen = bb.getShort() & 0xffff;
				NetFlowV9FieldType type = NetFlowV9FieldType.parse(fieldType);
				t.getDefinitions().add(new NetFlowV9FieldDef(type, fieldLen));
			}

			templates.add(t);
			p += 4 + t.getFieldCount() * 4;
		}

		return templates;
	}

	public static NetFlowV9OptionTemplate parseOptionTemplate(ByteBuffer bb) {
		NetFlowV9OptionTemplate optTemplate = new NetFlowV9OptionTemplate();

		int length = bb.getShort() & 0xffff;
		optTemplate.setTemplateId(bb.getShort() & 0xffff);

		int optionScopeLength = bb.getShort() & 0xffff;
		int optionLength = bb.getShort() & 0xffff;

		int p = bb.position();
		int endOfScope = p + optionScopeLength;
		int endOfOption = endOfScope + optionLength;
		int endOfTemplate = p - 10 + length;

		while (bb.position() < endOfScope) {
			int scopeType = bb.getShort() & 0xffff;
			int scopeLength = bb.getShort() & 0xffff;
			optTemplate.getScopeDefs().add(new NetFlowV9ScopeDef(scopeType, scopeLength));
		}

		// skip padding
		bb.position(endOfScope);

		while (bb.position() < endOfOption) {
			int optType = bb.getShort() & 0xffff;
			int optLength = bb.getShort() & 0xffff;
			NetFlowV9FieldType t = NetFlowV9FieldType.parse(optType);
			optTemplate.getOptionDefs().add(new NetFlowV9FieldDef(t, optLength));
		}

		// skip padding
		bb.position(endOfTemplate);

		return optTemplate;
	}

	public static List<NetFlowV9Record> parseRecords(ByteBuffer bb, NetFlowV9TemplateCache cache) {
		List<NetFlowV9Record> records = new ArrayList<NetFlowV9Record>();
		int flowSetId = bb.getShort() & 0xffff;
		int length = bb.getShort() & 0xffff;
		int end = bb.position() - 4 + length;

		List<NetFlowV9FieldDef> defs = null;

		boolean isOptionTemplate = cache.getOptionTemplate() != null && cache.getOptionTemplate().getTemplateId() == flowSetId;
		if (isOptionTemplate) {
			defs = cache.getOptionTemplate().getOptionDefs();
		} else {
			NetFlowV9Template t = cache.getTemplates().get(flowSetId);
			if (t == null)
				return null;
			defs = t.getDefinitions();
		}

		// calculate record unit size
		int unitSize = 0;
		for (NetFlowV9FieldDef def : defs)
			unitSize += def.getLength();

		while (bb.position() < end && bb.remaining() >= unitSize) {
			NetFlowV9Record r = null;

			if (isOptionTemplate) {
				NetFlowV9OptionRecord optRecord = new NetFlowV9OptionRecord();
				for (NetFlowV9ScopeDef def : cache.getOptionTemplate().getScopeDefs()) {
					int t = def.getType();
					int len = def.getLength();

					long l = 0;
					for (int i = 0; i < len; i++) {
						l <<= 8;
						l |= bb.get() & 0xff;
					}

					optRecord.getScopes().put(t, l);
				}

				r = optRecord;
			} else
				r = new NetFlowV9Record();

			Map<String, Object> fields = r.getFields();
			for (NetFlowV9FieldDef def : defs) {
				Object value = def.parse(bb);
				String key = def.getType().name().toLowerCase();
				fields.put(key, value);
			}

			records.add(r);
		}

		bb.position(end);
		return records;
	}
}
