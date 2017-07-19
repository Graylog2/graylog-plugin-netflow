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

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import io.netty.buffer.ByteBuf;
import org.graylog.plugins.netflow.flows.InvalidFlowVersionException;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;


public class NetFlowV9Parser {
    public static NetFlowV9Packet parsePacket(ByteBuf bb, NetFlowV9TemplateCache cache) {
        final int dataLength = bb.readableBytes();
        final NetFlowV9Header header = parseHeader(bb);

        List<NetFlowV9Template> templates = Collections.emptyList();
        NetFlowV9OptionTemplate optTemplate = null;
        List<NetFlowV9BaseRecord> records = Collections.emptyList();
        while (bb.isReadable()) {
            bb.markReaderIndex();
            int flowSetId = bb.readUnsignedShort();
            if (flowSetId == 0) {
                templates = parseTemplates(bb);
                for (NetFlowV9Template t : templates) {
                    cache.getTemplates().put(t.templateId(), t);
                }
            } else if (flowSetId == 1) {
                optTemplate = parseOptionTemplate(bb);
                cache.setOptionTemplate(optTemplate);
            } else {
                bb.resetReaderIndex();
                records = parseRecords(bb, cache);
            }
        }

        return NetFlowV9Packet.create(
                header,
                templates,
                optTemplate,
                records,
                dataLength);
    }

    public static NetFlowV9Header parseHeader(ByteBuf bb) {
        final int version = bb.readUnsignedShort();
        if (version != 9) {
            throw new InvalidFlowVersionException(version);
        }

        final int count = bb.readUnsignedShort();
        final long sysUptime = bb.readUnsignedInt();
        final long unixSecs = bb.readUnsignedInt();
        final long sequence = bb.readUnsignedInt();
        final long sourceId = bb.readUnsignedInt();

        return NetFlowV9Header.create(version, count, sysUptime, unixSecs, sequence, sourceId);
    }

    public static List<NetFlowV9Template> parseTemplates(ByteBuf bb) {
        final ImmutableList.Builder<NetFlowV9Template> templates = ImmutableList.builder();
        int len = bb.readUnsignedShort();

        int p = 4; // flow set id and length field itself
        while (p < len) {
            final int templateId = bb.readUnsignedShort();
            final int fieldCount = bb.readUnsignedShort();
            final ImmutableList.Builder<NetFlowV9FieldDef> fieldDefs = ImmutableList.builder();
            for (int i = 0; i < fieldCount; i++) {
                int fieldType = bb.readUnsignedShort();
                int fieldLen = bb.readUnsignedShort();
                final NetFlowV9FieldType type = NetFlowV9FieldType.parse(fieldType);
                final NetFlowV9FieldDef fieldDef = NetFlowV9FieldDef.create(type, fieldLen);
                fieldDefs.add(fieldDef);
            }

            final NetFlowV9Template template = NetFlowV9Template.create(templateId, fieldCount, fieldDefs.build());
            templates.add(template);

            p += 4 + template.fieldCount() * 4;
        }

        return templates.build();
    }

    public static NetFlowV9OptionTemplate parseOptionTemplate(ByteBuf bb) {
        int length = bb.readUnsignedShort();
        final int templateId = bb.readUnsignedShort();

        int optionScopeLength = bb.readUnsignedShort();
        int optionLength = bb.readUnsignedShort();

        int p = bb.readerIndex();
        int endOfScope = p + optionScopeLength;
        int endOfOption = endOfScope + optionLength;
        int endOfTemplate = p - 10 + length;

        final ImmutableList.Builder<NetFlowV9ScopeDef> scopeDefs = ImmutableList.builder();
        while (bb.readerIndex() < endOfScope) {
            int scopeType = bb.readUnsignedShort();
            int scopeLength = bb.readUnsignedShort();
            scopeDefs.add(NetFlowV9ScopeDef.create(scopeType, scopeLength));
        }

        // skip padding
        bb.readerIndex(endOfScope);

        final ImmutableList.Builder<NetFlowV9FieldDef> optionDefs = ImmutableList.builder();
        while (bb.readerIndex() < endOfOption) {
            int optType = bb.readUnsignedShort();
            int optLength = bb.readUnsignedShort();
            NetFlowV9FieldType t = NetFlowV9FieldType.parse(optType);
            optionDefs.add(NetFlowV9FieldDef.create(t, optLength));
        }

        // skip padding
        bb.readerIndex(endOfTemplate);

        return NetFlowV9OptionTemplate.create(templateId, scopeDefs.build(), optionDefs.build());
    }

    public static List<NetFlowV9BaseRecord> parseRecords(ByteBuf bb, NetFlowV9TemplateCache cache) {
        List<NetFlowV9BaseRecord> records = new ArrayList<>();
        int flowSetId = bb.readUnsignedShort();
        int length = bb.readUnsignedShort();
        int end = bb.readerIndex() - 4 + length;

        List<NetFlowV9FieldDef> defs = null;

        boolean isOptionTemplate = cache.getOptionTemplate() != null && cache.getOptionTemplate().templateId() == flowSetId;
        if (isOptionTemplate) {
            defs = cache.getOptionTemplate().optionDefs();
        } else {
            NetFlowV9Template t = cache.getTemplates().get(flowSetId);
            if (t == null) {
                return Collections.emptyList();
            }
            defs = t.definitions();
        }

        // calculate record unit size
        int unitSize = 0;
        for (NetFlowV9FieldDef def : defs) {
            unitSize += def.length();
        }

        while (bb.readerIndex() < end && bb.readableBytes() >= unitSize) {
            final ImmutableMap.Builder<String, Object> fields = ImmutableMap.builder();
            for (NetFlowV9FieldDef def : defs) {
                final String key = def.type().name().toLowerCase();
                final Optional<Object> optValue = def.parse(bb);
                optValue.ifPresent(value -> fields.put(key, value));
            }

            if (isOptionTemplate) {
                final ImmutableMap.Builder<Integer, Object> scopes = ImmutableMap.builder();
                for (NetFlowV9ScopeDef def : cache.getOptionTemplate().scopeDefs()) {
                    int t = def.type();
                    int len = def.length();

                    long l = 0;
                    for (int i = 0; i < len; i++) {
                        l <<= 8;
                        l |= bb.readUnsignedByte();
                    }

                    scopes.put(t, l);
                }

                records.add(NetFlowV9OptionRecord.create(fields.build(), scopes.build()));
            } else {
                records.add(NetFlowV9Record.create(fields.build()));
            }
        }

        bb.readerIndex(end);
        return records;
    }
}
