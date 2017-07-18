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

import io.netty.buffer.ByteBuf;

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
    public static NetFlowV9Packet parsePacket(ByteBuf bb, NetFlowV9TemplateCache cache) {
        NetFlowV9Packet p = new NetFlowV9Packet();
        p.setDataLength(bb.readableBytes());
        NetFlowV9Header header = parseHeader(bb);

        p.setHeader(header);

        while (bb.isReadable()) {
            bb.markReaderIndex();
            int flowSetId = bb.readUnsignedShort();
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
                bb.resetReaderIndex();
                List<NetFlowV9Record> r = parseRecords(bb, cache);
                p.setRecords(r);
            }
        }

        return p;
    }

    public static NetFlowV9Header parseHeader(ByteBuf bb) {
        NetFlowV9Header h = new NetFlowV9Header();
        h.setVersion(bb.readUnsignedShort());
        h.setCount(bb.readUnsignedShort());
        h.setSysUptime(bb.readUnsignedInt());
        h.setUnixSecs(bb.readUnsignedInt());
        h.setSequence(bb.readUnsignedInt());
        h.setSourceId(bb.readUnsignedInt());

        return h;
    }

    public static List<NetFlowV9Template> parseTemplates(ByteBuf bb) {
        List<NetFlowV9Template> templates = new ArrayList<>();
        int len = bb.readUnsignedShort();

        int p = 4; // flow set id and length field itself
        while (p < len) {
            NetFlowV9Template t = new NetFlowV9Template();
            t.setTemplateId(bb.readUnsignedShort());
            t.setFieldCount(bb.readUnsignedShort());

            for (int i = 0; i < t.getFieldCount(); i++) {
                int fieldType = bb.readUnsignedShort();
                int fieldLen = bb.readUnsignedShort();
                NetFlowV9FieldType type = NetFlowV9FieldType.parse(fieldType);
                t.getDefinitions().add(new NetFlowV9FieldDef(type, fieldLen));
            }

            templates.add(t);
            p += 4 + t.getFieldCount() * 4;
        }

        return templates;
    }

    public static NetFlowV9OptionTemplate parseOptionTemplate(ByteBuf bb) {
        NetFlowV9OptionTemplate optTemplate = new NetFlowV9OptionTemplate();

        int length = bb.readUnsignedShort();
        optTemplate.setTemplateId(bb.readUnsignedShort());

        int optionScopeLength = bb.readUnsignedShort();
        int optionLength = bb.readUnsignedShort();

        int p = bb.readerIndex();
        int endOfScope = p + optionScopeLength;
        int endOfOption = endOfScope + optionLength;
        int endOfTemplate = p - 10 + length;

        while (bb.readerIndex() < endOfScope) {
            int scopeType = bb.readUnsignedShort();
            int scopeLength = bb.readUnsignedShort();
            optTemplate.getScopeDefs().add(new NetFlowV9ScopeDef(scopeType, scopeLength));
        }

        // skip padding
        bb.readerIndex(endOfScope);

        while (bb.readerIndex() < endOfOption) {
            int optType = bb.readUnsignedShort();
            int optLength = bb.readUnsignedShort();
            NetFlowV9FieldType t = NetFlowV9FieldType.parse(optType);
            optTemplate.getOptionDefs().add(new NetFlowV9FieldDef(t, optLength));
        }

        // skip padding
        bb.readerIndex(endOfTemplate);

        return optTemplate;
    }

    public static List<NetFlowV9Record> parseRecords(ByteBuf bb, NetFlowV9TemplateCache cache) {
        List<NetFlowV9Record> records = new ArrayList<>();
        int flowSetId = bb.readUnsignedShort();
        int length = bb.readUnsignedShort();
        int end = bb.readerIndex() - 4 + length;

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

        while (bb.readerIndex() < end && bb.readableBytes() >= unitSize) {
            NetFlowV9Record r = null;

            if (isOptionTemplate) {
                NetFlowV9OptionRecord optRecord = new NetFlowV9OptionRecord();
                for (NetFlowV9ScopeDef def : cache.getOptionTemplate().getScopeDefs()) {
                    int t = def.getType();
                    int len = def.getLength();

                    long l = 0;
                    for (int i = 0; i < len; i++) {
                        l <<= 8;
                        l |= bb.readUnsignedByte();
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

        bb.readerIndex(end);
        return records;
    }
}
